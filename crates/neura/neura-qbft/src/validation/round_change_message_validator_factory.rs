use std::sync::Arc;
use crate::types::QbftConfig;
use crate::validation::MessageValidatorFactory;
use crate::validation::RoundChangeMessageValidator;
use crate::validation::round_change_message_validator::RoundChangeMessageValidatorImpl;

/// Factory for creating `RoundChangeMessageValidator` instances.
pub trait RoundChangeMessageValidatorFactory: Send + Sync {
    /// Creates a `RoundChangeMessageValidator`.
    fn create_round_change_message_validator(&self) -> Arc<dyn RoundChangeMessageValidator + Send + Sync>;
}

/// Concrete implementation of RoundChangeMessageValidatorFactory.
pub struct RoundChangeMessageValidatorFactoryImpl {
    /// Dependencies needed by RoundChangeMessageValidatorImpl
    message_validator_factory: Arc<dyn MessageValidatorFactory>,
    config: Arc<QbftConfig>,
}

impl RoundChangeMessageValidatorFactoryImpl {
    pub fn new(message_validator_factory: Arc<dyn MessageValidatorFactory>, config: Arc<QbftConfig>) -> Self {
        Self { message_validator_factory, config }
    }
}

impl RoundChangeMessageValidatorFactory for RoundChangeMessageValidatorFactoryImpl {
    fn create_round_change_message_validator(&self) -> Arc<dyn RoundChangeMessageValidator + Send + Sync> {
        // Obtain necessary validators from the MessageValidatorFactory
        let proposal_validator = self.message_validator_factory.clone().create_proposal_validator();
        let prepare_validator = self.message_validator_factory.clone().create_prepare_validator();
        
        // Pass the factory's dependencies and the obtained validators to the new RoundChangeMessageValidatorImpl instance.
        Arc::new(RoundChangeMessageValidatorImpl::new(
            self.config.clone(),
            proposal_validator,
            prepare_validator,
            self.message_validator_factory.clone(), 
        ))
    }
} 