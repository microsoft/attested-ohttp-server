use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyModule, PyString, PyTuple};
use std::str;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

pub fn get_token(app_data: &[u8], endpoint_url: &str) -> Res<Vec<u8>> {
    // Acquire the Python GIL (Global Interpreter Lock)
    Python::with_gil(|py| {
        // Import necessary Python modules and classes
        tracing::info!("Importing Python modules...");
        let client_module = PyModule::import(py, "attest")?;
        let attestation_client_class = client_module.getattr("AttestationClient")?;
        let attestation_params_class = client_module.getattr("AttestationClientParameters")?;
        let verifier_enum = client_module.getattr("Verifier")?;
        let isolation_type_enum = client_module.getattr("IsolationType")?;
        tracing::info!("Python modules imported successfully.");

        // --- Prepare AttestationClientParameters ---
        tracing::info!("Preparing AttestationClientParameters...");
        let verifier = verifier_enum.getattr("MAA")?;
        let isolation_type = isolation_type_enum.getattr("TDX")?;

        // Convert app_data (claims JSON bytes) to Python object (dict)
        let claims_json_str = str::from_utf8(app_data)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("app_data is not valid UTF-8: {}", e)))?;
        let json_module = PyModule::import(py, "json")?;
        let claims_py_object = json_module.call_method1("loads", (claims_json_str,))?;
        let api_key = py.None();
        let maa_endpoint = PyString::new(py, endpoint_url);

        // Create AttestationClientParameters instance
        // Pass arguments directly where appropriate (Bound<'_...>, Py<...>)
        let params_args_tuple = (maa_endpoint, verifier, isolation_type, claims_py_object, api_key).into_pyobject(py)?;

        // Handle the Result from PyTuple::new before passing to call1
        let client_params = attestation_params_class.call1(params_args_tuple)?;
        tracing::info!("AttestationClientParameters created.");

        // --- Instantiate AttestationClient ---
        tracing::info!("Instantiating AttestationClient...");
        // Need a logger instance. Use the Logger class from src.Logger.
        let logger_module_name = "src.Logger";
        let logger_module = PyModule::import(py, logger_module_name)?;
        let logger_class = logger_module.getattr("Logger")?;
        let py_logger_instance = logger_class.call1((PyString::new(py, "rust_caller"),))?;
        let py_logger = py_logger_instance.call_method0("get_logger")?;

        // Handle the Result from PyTuple::new before passing to call1
        let client_args_tuple = PyTuple::new(py, &[py_logger, client_params]);
        let client_instance = attestation_client_class.call1(client_args_tuple?)?;
        tracing::info!("AttestationClient instantiated.");

        // --- Call attest_platform ---
        tracing::info!("Calling attest_platform...");
        let token_py_obj = client_instance.call_method0("attest_platform")?;

        // Check if the result is None (Python None) which might indicate an error during attestation
        if token_py_obj.is_none() {
             return Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "Python attest_platform returned None, indicating an error during attestation.",
            ));
        }

        // Cast the result to PyString using downcast::<T>()? which returns &Bound<'_, T>
        let token_py_string = token_py_obj.downcast::<PyString>()?;
        tracing::info!("attest_guest call successful.");

        // Convert the Python string token to Rust Vec<u8>
        let token_str = token_py_string.to_str()?;
        Ok(token_str.as_bytes().to_vec())

    }).map_err(|e| {
        // Convert PyO3 error to Box<dyn std::error::Error>
        Python::with_gil(|py| {
             e.print(py); // Print Python traceback to stderr
        });
        let err_msg = format!("Python execution error: {}", e);
        tracing::error!("{}", err_msg);
        Box::<dyn std::error::Error>::from(err_msg)
    })
}
