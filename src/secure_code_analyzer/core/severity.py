"""
Severity classification logic for vulnerability findings.
Provides consistent severity levels and scoring across all detections.
"""

from enum import Enum
from typing import Dict, Any, Optional
from dataclasses import dataclass


class SeverityLevel(Enum):
    """Enumeration of severity levels from lowest to highest."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Severity level metadata
SEVERITY_METADATA: Dict[SeverityLevel, Dict[str, Any]] = {
    SeverityLevel.CRITICAL: {
        "score": 9.0,
        "score_range": (9.0, 10.0),
        "color": "#dc2626",  # Red
        "priority": 1,
        "description": "Critical vulnerabilities that require immediate attention. "
                      "These can lead to full system compromise, data breach, or "
                      "remote code execution.",
        "remediation_urgency": "Immediate - within 24 hours"
    },
    SeverityLevel.HIGH: {
        "score": 7.0,
        "score_range": (7.0, 8.9),
        "color": "#ea580c",  # Orange
        "priority": 2,
        "description": "High severity vulnerabilities that pose significant risk. "
                      "These can lead to unauthorized access, privilege escalation, "
                      "or significant data exposure.",
        "remediation_urgency": "Urgent - within 1 week"
    },
    SeverityLevel.MEDIUM: {
        "score": 4.0,
        "score_range": (4.0, 6.9),
        "color": "#ca8a04",  # Yellow
        "priority": 3,
        "description": "Medium severity vulnerabilities that should be addressed. "
                      "These may lead to limited data exposure or require specific "
                      "conditions to exploit.",
        "remediation_urgency": "Normal - within 1 month"
    },
    SeverityLevel.LOW: {
        "score": 2.0,
        "score_range": (0.1, 3.9),
        "color": "#2563eb",  # Blue
        "priority": 4,
        "description": "Low severity vulnerabilities with minimal impact. "
                      "These may indicate bad practices or minor information disclosure.",
        "remediation_urgency": "Low - within 3 months"
    },
    SeverityLevel.INFO: {
        "score": 0.0,
        "score_range": (0.0, 0.0),
        "color": "#6b7280",  # Gray
        "priority": 5,
        "description": "Informational findings that may indicate code quality issues "
                      "or potential improvements but do not pose direct security risks.",
        "remediation_urgency": "Optional - as time permits"
    }
}


@dataclass
class SeverityClassification:
    """Data class representing a severity classification result."""
    level: SeverityLevel
    score: float
    confidence: float
    factors: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        metadata = SEVERITY_METADATA[self.level]
        return {
            "level": self.level.value,
            "score": self.score,
            "confidence": self.confidence,
            "color": metadata["color"],
            "priority": metadata["priority"],
            "description": metadata["description"],
            "remediation_urgency": metadata["remediation_urgency"],
            "factors": self.factors
        }


def get_severity_from_string(severity_str: str) -> SeverityLevel:
    """
    Convert a severity string to SeverityLevel enum.
    
    Args:
        severity_str: String representation of severity
        
    Returns:
        Corresponding SeverityLevel enum value
    """
    severity_map = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
        "informational": SeverityLevel.INFO,
        "warning": SeverityLevel.LOW,
    }
    return severity_map.get(severity_str.lower(), SeverityLevel.INFO)


def get_severity_from_score(score: float) -> SeverityLevel:
    """
    Determine severity level from a numeric score.
    
    Args:
        score: Numeric score (0.0 - 10.0)
        
    Returns:
        Corresponding SeverityLevel
    """
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    elif score >= 7.0:
        return SeverityLevel.HIGH
    elif score >= 4.0:
        return SeverityLevel.MEDIUM
    elif score > 0.0:
        return SeverityLevel.LOW
    else:
        return SeverityLevel.INFO


def classify_severity(
    rule_severity: str,
    vulnerability_type: str,
    context: Optional[Dict[str, Any]] = None
) -> SeverityClassification:
    """
    Classify the severity of a finding based on multiple factors.
    
    This function considers:
    - The rule's defined severity
    - The type of vulnerability
    - Contextual factors (e.g., is it in authentication code?)
    
    Args:
        rule_severity: Severity defined in the rule
        vulnerability_type: Type/category of the vulnerability
        context: Additional context for classification
        
    Returns:
        SeverityClassification with detailed scoring
    """
    context = context or {}
    factors = {}
    
    # Start with base severity from rule
    base_level = get_severity_from_string(rule_severity)
    base_score = SEVERITY_METADATA[base_level]["score"]
    
    factors["base_severity"] = rule_severity
    
    # Adjust based on vulnerability type
    type_adjustments = {
        "sql_injection": 1.5,
        "command_injection": 2.0,
        "xss": 1.0,
        "path_traversal": 1.0,
        "hardcoded_secret": 1.5,
        "weak_crypto": 0.5,
        "insecure_random": 0.5,
        "information_disclosure": 0.0,
        "code_quality": -0.5,
    }
    
    type_key = vulnerability_type.lower().replace(" ", "_").replace("-", "_")
    type_adjustment = type_adjustments.get(type_key, 0.0)
    factors["type_adjustment"] = type_adjustment
    
    # Context-based adjustments
    context_adjustment = 0.0
    
    if context.get("in_authentication_code"):
        context_adjustment += 1.0
        factors["auth_code_boost"] = 1.0
        
    if context.get("in_payment_code"):
        context_adjustment += 1.0
        factors["payment_code_boost"] = 1.0
        
    if context.get("user_input_nearby"):
        context_adjustment += 0.5
        factors["user_input_boost"] = 0.5
        
    if context.get("is_test_file"):
        context_adjustment -= 1.0
        factors["test_file_reduction"] = -1.0
    
    factors["context_adjustment"] = context_adjustment
    
    # Calculate final score (capped at 10.0)
    final_score = min(10.0, max(0.0, base_score + type_adjustment + context_adjustment))
    final_level = get_severity_from_score(final_score)
    
    # Calculate confidence based on how much context we have
    confidence = 0.7  # Base confidence
    if context:
        confidence += 0.1 * min(len(context), 3)
    confidence = min(1.0, confidence)
    
    return SeverityClassification(
        level=final_level,
        score=round(final_score, 2),
        confidence=round(confidence, 2),
        factors=factors
    )


def get_severity_summary(findings: list) -> Dict[str, Any]:
    """
    Generate a summary of severity distribution across findings.
    
    Args:
        findings: List of finding dictionaries with 'severity' key
        
    Returns:
        Summary dictionary with counts and statistics
    """
    summary = {
        "total": len(findings),
        "by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "risk_score": 0.0
    }
    
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        if severity in summary["by_severity"]:
            summary["by_severity"][severity] += 1
    
    # Calculate weighted risk score
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    total_weight = sum(
        count * weights.get(sev, 0) 
        for sev, count in summary["by_severity"].items()
    )
    
    if summary["total"] > 0:
        summary["risk_score"] = round(total_weight / summary["total"], 2)
    
    return summary


def compare_severity(sev1: str, sev2: str) -> int:
    """
    Compare two severity levels.
    
    Args:
        sev1: First severity level string
        sev2: Second severity level string
        
    Returns:
        -1 if sev1 < sev2, 0 if equal, 1 if sev1 > sev2
    """
    level1 = get_severity_from_string(sev1)
    level2 = get_severity_from_string(sev2)
    
    priority1 = SEVERITY_METADATA[level1]["priority"]
    priority2 = SEVERITY_METADATA[level2]["priority"]
    
    # Lower priority number means higher severity
    if priority1 < priority2:
        return 1
    elif priority1 > priority2:
        return -1
    return 0
