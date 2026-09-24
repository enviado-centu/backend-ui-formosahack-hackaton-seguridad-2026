"""Risk assessment service."""

import logging
from typing import Optional

from ..schemas.scan import (
    KevSignals,
    RulesSignals,
    MLSignals,
    RiskAssessment,
)

logger = logging.getLogger(__name__)


class RiskService:
    """Service for combining signals and assessing risk."""
    
    def assess_risk(
        self,
        kev: KevSignals,
        rules: RulesSignals,
        ml: MLSignals,
    ) -> RiskAssessment:
        """Combine signals from all engines and assess overall risk.
        
        Algorithm:
        - If Kev is available: 50% Kev + 25% rules + 25% ML
        - If Kev is not available: 60% rules + 40% ML
        - If ML is not available: 70% rules + 30% Kev (if available)
        - If only rules: 100% rules
        """
        logger.info("Assessing risk from signals")
        
        signals = []
        weights = []
        
        if kev.available and kev.is_phishing is not None:
            signals.append(kev.is_phishing)
            weights.append(0.50)
            logger.debug(f"Kev signal: {kev.is_phishing:.2f} (weight: 0.50)")
        
        if rules.available:
            signals.append(rules.risk_score)
            weights.append(0.25 if kev.available else 0.60)
            logger.debug(f"Rules signal: {rules.risk_score:.2f} (weight: {weights[-1]:.2f})")
        
        if ml.available and ml.score is not None:
            signals.append(ml.score)
            weights.append(0.25 if kev.available else 0.40)
            logger.debug(f"ML signal: {ml.score:.2f} (weight: {weights[-1]:.2f})")
        
        if not signals:
            logger.warning("No signals available for risk assessment")
            return RiskAssessment(
                score=0.0,
                level="unknown",
                classification_type=None,
                classification_probability=None,
            )
        
        total_weight = sum(weights)
        if total_weight > 0:
            normalized_weights = [w / total_weight for w in weights]
            risk_score = sum(s * w for s, w in zip(signals, normalized_weights))
        else:
            risk_score = sum(signals) / len(signals)
        
        risk_score = max(0.0, min(1.0, risk_score))
        
        risk_level = self._calculate_risk_level(risk_score)
        classification_type, classification_prob = self._determine_classification(
            kev, rules, ml
        )
        
        logger.info(
            f"Risk assessment complete: score={risk_score:.2f}, "
            f"level={risk_level}, classification={classification_type}"
        )
        
        return RiskAssessment(
            score=risk_score,
            level=risk_level,
            classification_type=classification_type,
            classification_probability=classification_prob,
        )
    
    def _calculate_risk_level(self, score: float) -> str:
        """Convert risk score to risk level."""
        if score < 0.2:
            return "low"
        elif score < 0.5:
            return "medium"
        elif score < 0.8:
            return "high"
        else:
            return "critical"
    
    def _determine_classification(
        self,
        kev: KevSignals,
        rules: RulesSignals,
        ml: MLSignals,
    ) -> tuple[Optional[str], Optional[float]]:
        """Determine threat classification from signals."""
        if kev.available and kev.threat_type:
            return kev.threat_type, kev.threat_confidence
        
        if ml.available and ml.prediction is not None:
            if ml.prediction == 0:
                return "phishing", ml.confidence
            else:
                return "benign", ml.confidence
        
        if rules.available and rules.rule_count > 0:
            if rules.rule_count >= 5:
                return "phishing", 0.7
            elif rules.rule_count >= 3:
                return "suspicious", 0.5
            else:
                return "low_risk", 0.3
        
        return "unknown", None
