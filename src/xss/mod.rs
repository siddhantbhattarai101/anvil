// ANVIL XSS Detection Module
// Professional evidence-driven, context-first XSS detection

pub mod context;
pub mod reflect;
pub mod payloads;
pub mod validate;
pub mod engine;
pub mod stored;
pub mod dom;
pub mod blind;
pub mod headless;

// Re-export types
pub use context::{XssContext, ContextAnalysis, QuoteType};
pub use reflect::{ReflectionPoint, ReflectionDiscovery, discover_reflections};
pub use payloads::{XssPayload, PayloadSet, load_payloads_for_context};
pub use validate::{XssValidationResult, ExecutionSeverity, validate_execution_likelihood};
pub use engine::XssScanner;
pub use stored::StoredXssEngine;
pub use dom::{DomXssFlow, analyze_dom_xss};
pub use blind::BlindXssEngine;
