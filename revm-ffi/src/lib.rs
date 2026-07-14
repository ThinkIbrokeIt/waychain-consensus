use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use alloy_primitives::{keccak256, Address, Bytes, U256};
use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, Bytecode, Env, ExecutionResult, ResultAndState, SpecId, TransactTo, TxEnv},
    DatabaseCommit, Evm,
};

macro_rules! bail {
    ($fmt:literal $(, $arg:expr)*) => {
        return ExecuteResponse {
            success: false, return_data: String::new(), gas_used: 0,
            error: Some(format!($fmt $(, $arg)*)),
            state: None, new_contract: None,
        }
    };
}

#[no_mangle]
pub extern "C" fn revm_execute(input: *const c_char) -> *mut c_char {
    let c_str = unsafe { CStr::from_ptr(input) };
    let input_str = match c_str.to_str() {
        Ok(s) => s,
        Err(e) => {
            let resp = ExecuteResponse {
                success: false, return_data: String::new(), gas_used: 0,
                error: Some(format!("invalid utf8: {e}")), state: None, new_contract: None,
            };
            return CString::new(serde_json::to_string(&resp).unwrap()).unwrap().into_raw();
        }
    };
    let result = match serde_json::from_str::<ExecuteRequest>(input_str) {
        Ok(req) => run_execute(req),
        Err(e) => ExecuteResponse {
            success: false, return_data: String::new(), gas_used: 0,
            error: Some(format!("json parse: {e}")), state: None, new_contract: None,
        },
    };
    CString::new(serde_json::to_string(&result).unwrap()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn revm_free_string(ptr: *mut c_char) {
    if !ptr.is_null() { drop(unsafe { CString::from_raw(ptr) }); }
}

#[derive(serde::Deserialize)]
struct ExecuteRequest {
    caller: String, address: String, value: Option<String>,
    gas_limit: u64, calldata: String, code: String,
    is_create: bool, state: Option<HashMap<String, AccountState>>,
}
#[derive(serde::Deserialize)]
struct AccountState {
    nonce: u64, balance: String, code: Option<String>,
    storage: Option<HashMap<String, String>>,
}
#[derive(serde::Serialize)]
struct ExecuteResponse {
    success: bool, return_data: String, gas_used: u64,
    error: Option<String>, state: Option<HashMap<String, AccountStateOut>>,
    new_contract: Option<String>,
}
#[derive(serde::Serialize)]
struct AccountStateOut {
    nonce: u64, balance: String, code: Option<String>,
    storage: Option<HashMap<String, String>>,
}

fn run_execute(req: ExecuteRequest) -> ExecuteResponse {
    let mut db = CacheDB::new(EmptyDB::default());

    if let Some(states) = &req.state {
        for (addr_str, acc_state) in states {
            let addr = match parse_addr(addr_str) { Ok(a) => a, Err(e) => bail!("bad addr: {e}") };
            let balance = match parse_u256(&acc_state.balance) { Ok(b) => b, Err(e) => bail!("bad balance: {e}") };
            let bytecode = acc_state.code.as_deref()
                .and_then(|c| hex::decode(c).ok())
                .map(|b| Bytecode::new_raw(Bytes::from(b)))
                .unwrap_or_default();
            let info = AccountInfo { balance, nonce: acc_state.nonce, code_hash: bytecode.hash_slow(), code: Some(bytecode) };
            db.insert_account_info(addr, info);

            if let Some(storage) = &acc_state.storage {
                if let Some(acct) = db.accounts.get_mut(&addr) {
                    for (k, v) in storage {
                        let key = match parse_u256(k) {
                            Ok(u) => u,
                            Err(e) => bail!("bad storage key: {e}"),
                        };
                        let val = match parse_u256(v) {
                            Ok(u) => u,
                            Err(e) => bail!("bad storage val: {e}"),
                        };
                        acct.storage.insert(key, val);
                    }
                }
            }
        }
    }

    let caller = match parse_addr(&req.caller) { Ok(a) => a, Err(e) => bail!("bad caller: {e}") };
    let calldata_bytes = match hex::decode(&req.calldata) { Ok(b) => b, Err(e) => bail!("bad calldata: {e}") };
    let _code = match hex::decode(&req.code) { Ok(b) => b, Err(e) => bail!("bad code: {e}") };
    let value = match &req.value {
        Some(v) => match parse_u256(v) { Ok(u) => u, Err(e) => bail!("bad value: {e}") },
        None => U256::ZERO,
    };

    let mut env = Env::default();
    env.cfg.chain_id = 10008;
    env.block.gas_limit = U256::from(30_000_000u64);
    let transact_to = if req.is_create {
        TransactTo::Create
    } else {
        TransactTo::Call(match parse_addr(&req.address) { Ok(a) => a, Err(e) => bail!("bad target: {e}") })
    };
    env.tx = TxEnv {
        caller, gas_limit: req.gas_limit, gas_price: U256::from(1),
        transact_to, value, data: Bytes::from(calldata_bytes),
        nonce: None, chain_id: Some(10008), ..Default::default()
    };

    let (_result, state, success, return_data, gas_used, error) = {
        let mut evm = Evm::builder()
            .with_db(&mut db)
            .with_spec_id(SpecId::CANCUN)
            .with_env(Box::new(env))
            .build();

        let result = match evm.transact() { Ok(r) => r, Err(e) => bail!("tx error: {e:?}") };
        let ResultAndState { result, state } = result;

        let (success, return_data, gas_used, error) = match &result {
            ExecutionResult::Success { output, gas_used, .. } =>
                (true, hex::encode(output.data().as_ref()), *gas_used, None),
            ExecutionResult::Revert { output, gas_used } => {
                let reason = if output.len() > 4 { String::from_utf8_lossy(&output[4..]).to_string() } else { "revert".into() };
                (false, String::new(), *gas_used, Some(reason))
            }
            ExecutionResult::Halt { reason, gas_used } =>
                (false, String::new(), *gas_used, Some(format!("halt: {reason:?}"))),
        };
        (result, state, success, return_data, gas_used, error)
    }; // evm dropped here, mutable borrow released

    db.commit(state);

    // Extract modified accounts
    let mut state_out: HashMap<String, AccountStateOut> = HashMap::new();
    let known_addrs: Vec<String> = req.state.as_ref()
        .map(|s| s.keys().cloned().collect()).unwrap_or_default();

    for addr_str in &known_addrs {
        if let Ok(addr) = parse_addr(addr_str) {
            if let Some(acct) = db.accounts.get(&addr) {
                let mut storage = HashMap::new();
                for (k, v) in &acct.storage {
                    storage.insert(hex::encode(k.to_be_bytes::<32>()), hex::encode(v.to_be_bytes::<32>()));
                }
                state_out.insert(addr_str.clone(), AccountStateOut {
                    nonce: acct.info.nonce,
                    balance: format!("0x{:x}", acct.info.balance),
                    code: acct.info.code.as_ref().map(|c| hex::encode(c.bytes())),
                    storage: Some(storage),
                });
            }
        }
    }

    let new_contract = if req.is_create && success {
        let nonce = db.accounts.get(&caller).map(|a| a.info.nonce.saturating_sub(1)).unwrap_or(0);
        let addr = create_address(caller, nonce);
        let new_addr_str = hex::encode(addr.as_slice());
        if let Some(new_acct) = db.accounts.get(&addr) {
            let mut storage = HashMap::new();
            for (k, v) in &new_acct.storage {
                storage.insert(hex::encode(k.to_be_bytes::<32>()), hex::encode(v.to_be_bytes::<32>()));
            }
            state_out.insert(new_addr_str.clone(), AccountStateOut {
                nonce: new_acct.info.nonce,
                balance: format!("0x{:x}", new_acct.info.balance),
                code: new_acct.info.code.as_ref().map(|c| hex::encode(c.bytes())),
                storage: Some(storage),
            });
        }
        Some(new_addr_str)
    } else { None };

    ExecuteResponse {
        success, return_data, gas_used, error,
        state: if state_out.is_empty() { None } else { Some(state_out) },
        new_contract,
    }
}

fn parse_addr(s: &str) -> Result<Address, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| format!("hex: {e}"))?;
    if bytes.len() != 20 { return Err(format!("expected 20 bytes, got {}", bytes.len())); }
    let mut arr = [0u8; 20]; arr.copy_from_slice(&bytes);
    Ok(Address::from(arr))
}

fn parse_u256(s: &str) -> Result<U256, String> {
    U256::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).map_err(|e| format!("parse u256: {e}"))
}

fn create_address(caller: Address, nonce: u64) -> Address {
    let mut rlp = Vec::new();
    if nonce == 0 {
        rlp.push(0xc0 + 22); rlp.push(0x80 + 20); rlp.extend_from_slice(caller.as_slice()); rlp.push(0x80);
    } else {
        let nb = nonce.to_be_bytes();
        let stripped = &nb[nb.iter().position(|&b| b != 0).unwrap_or(7)..];
        rlp.push(0xc0 + (1 + 20 + 1 + stripped.len()) as u8);
        rlp.push(0x80 + 20); rlp.extend_from_slice(caller.as_slice());
        rlp.push(0x80 + stripped.len() as u8); rlp.extend_from_slice(stripped);
    }
    Address::from_slice(&keccak256(&rlp)[12..])
}