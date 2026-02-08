"""ROI calculation engine for bug bounty targeting."""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from loguru import logger

from ..core.database import Program, Vulnerability, Scan, get_async_db
from ..core.config import config

@dataclass
class TargetMetrics:
    """Metrics for a potential target."""
    program_id: int
    program_name: str
    target: str
    
    # Financial metrics
    min_bounty: float = 0.0
    max_bounty: float = 0.0
    avg_bounty: float = 0.0
    expected_bounty: float = 0.0
    
    # Difficulty metrics
    competition_level: float = 0.0  # 0-1 scale
    technical_complexity: float = 0.5  # 0-1 scale
    scope_breadth: int = 0
    
    # Historical metrics
    historical_success_rate: float = 0.0
    time_to_first_bug: float = 0.0  # hours
    avg_response_time: float = 0.0  # hours
    
    # Risk metrics
    compliance_risk: float = 0.0  # 0-1 scale
    reputation_risk: float = 0.0  # 0-1 scale
    
    # Calculated scores
    roi_score: float = 0.0
    priority_score: float = 0.0
    confidence: float = 0.0

@dataclass
class InvestmentParameters:
    """Parameters for time investment calculation."""
    research_hours: float = 2.0
    reconnaissance_hours: float = 4.0
    scanning_hours: float = 2.0
    manual_testing_hours: float = 8.0
    report_writing_hours: float = 2.0
    
    # Hourly rates for cost calculation
    researcher_hourly_rate: float = 75.0
    
    @property
    def total_hours(self) -> float:
        """Calculate total time investment."""
        return (self.research_hours + self.reconnaissance_hours + 
                self.scanning_hours + self.manual_testing_hours + 
                self.report_writing_hours)
    
    @property
    def total_cost(self) -> float:
        """Calculate total cost investment."""
        return self.total_hours * self.researcher_hourly_rate

class ROICalculator:
    """Advanced ROI calculator for bug bounty programs."""
    
    def __init__(self):
        """Initialize ROI calculator."""
        self.market_factors = {
            'platform_multipliers': {
                'hackerone': 1.2,
                'bugcrowd': 1.1,
                'intigriti': 1.0,
                'yeswehack': 0.95
            },
            'competition_factors': {
                'very_low': 1.5,
                'low': 1.2,
                'medium': 1.0,
                'high': 0.7,
                'very_high': 0.4
            }
        }
        
        # ML model for success prediction (placeholder)
        self.success_predictor = None
    
    async def calculate_target_metrics(self, program_id: int, target: str) -> TargetMetrics:
        """Calculate comprehensive metrics for a target."""
        try:
            async with get_async_db() as db:
                program = await db.get(Program, program_id)
                if not program:
                    raise ValueError(f"Program {program_id} not found")
                
                metrics = TargetMetrics(
                    program_id=program_id,
                    program_name=program.name,
                    target=target
                )
                
                # Basic financial metrics
                metrics.min_bounty = program.min_bounty or 0.0
                metrics.max_bounty = program.max_bounty or 0.0
                metrics.avg_bounty = program.avg_bounty or (metrics.min_bounty + metrics.max_bounty) / 2
                
                # Calculate expected bounty
                metrics.expected_bounty = await self._calculate_expected_bounty(program, target)
                
                # Competition analysis
                metrics.competition_level = await self._analyze_competition(program)
                
                # Technical complexity assessment
                metrics.technical_complexity = await self._assess_technical_complexity(program, target)
                
                # Historical performance
                metrics.historical_success_rate = await self._calculate_success_rate(program_id)
                metrics.time_to_first_bug = await self._calculate_avg_time_to_bug(program_id)
                
                # Risk assessment
                metrics.compliance_risk = await self._assess_compliance_risk(program, target)
                metrics.reputation_risk = await self._assess_reputation_risk(program)
                
                # Scope analysis
                metrics.scope_breadth = len(program.scope or [])
                metrics.avg_response_time = program.response_time_avg or 72.0  # Default 3 days
                
                # Calculate final scores
                metrics.roi_score = await self._calculate_roi_score(metrics)
                metrics.priority_score = await self._calculate_priority_score(metrics)
                metrics.confidence = await self._calculate_confidence(metrics, program)
                
                return metrics
                
        except Exception as e:
            logger.error(f"Failed to calculate target metrics: {e}")
            raise
    
    async def rank_targets(self, targets: List[Tuple[int, str]], 
                          strategy: str = 'balanced') -> List[TargetMetrics]:
        """Rank targets by different strategies."""
        target_metrics = []
        
        # Calculate metrics for all targets
        for program_id, target in targets:
            try:
                metrics = await self.calculate_target_metrics(program_id, target)
                target_metrics.append(metrics)
            except Exception as e:
                logger.error(f"Failed to calculate metrics for {target}: {e}")
        
        # Apply ranking strategy
        if strategy == 'roi_focused':
            target_metrics.sort(key=lambda x: x.roi_score, reverse=True)
        elif strategy == 'low_risk':
            target_metrics.sort(key=lambda x: (x.roi_score, -x.compliance_risk, -x.reputation_risk), reverse=True)
        elif strategy == 'quick_wins':
            target_metrics.sort(key=lambda x: (x.roi_score, -x.technical_complexity, -x.competition_level), reverse=True)
        elif strategy == 'high_value':
            target_metrics.sort(key=lambda x: x.expected_bounty, reverse=True)
        else:  # balanced
            target_metrics.sort(key=lambda x: x.priority_score, reverse=True)
        
        return target_metrics
    
    async def calculate_portfolio_roi(self, targets: List[TargetMetrics], 
                                    investment_params: InvestmentParameters) -> Dict[str, Any]:
        """Calculate ROI for a portfolio of targets."""
        total_expected_return = sum(t.expected_bounty * t.historical_success_rate for t in targets)
        total_investment = investment_params.total_cost * len(targets)
        
        if total_investment == 0:
            portfolio_roi = 0.0
        else:
            portfolio_roi = (total_expected_return - total_investment) / total_investment * 100
        
        # Risk-adjusted return
        avg_risk = np.mean([t.compliance_risk + t.reputation_risk for t in targets]) / 2
        risk_adjusted_roi = portfolio_roi * (1 - avg_risk)
        
        # Diversification score
        platforms = set(t.program_name for t in targets)
        diversification_score = min(1.0, len(platforms) / 5)  # Optimal: 5+ different platforms
        
        return {
            'total_expected_return': total_expected_return,
            'total_investment': total_investment,
            'portfolio_roi': portfolio_roi,
            'risk_adjusted_roi': risk_adjusted_roi,
            'diversification_score': diversification_score,
            'expected_bugs_per_month': sum(t.historical_success_rate for t in targets),
            'avg_time_per_bug': np.mean([t.time_to_first_bug for t in targets if t.time_to_first_bug > 0]),
            'confidence_interval': self._calculate_confidence_interval(targets)
        }
    
    async def optimize_portfolio(self, available_targets: List[TargetMetrics], 
                               max_targets: int = 10, 
                               budget_hours: float = 100.0) -> List[TargetMetrics]:
        """Optimize target portfolio using constrained optimization."""
        # Simple greedy optimization (in production, use proper optimization algorithms)
        targets = available_targets.copy()
        targets.sort(key=lambda x: x.roi_score / max(1.0, x.time_to_first_bug), reverse=True)
        
        selected = []
        total_hours = 0.0
        investment_params = InvestmentParameters()
        
        for target in targets:
            estimated_hours = investment_params.total_hours * (1 + target.technical_complexity)
            
            if len(selected) >= max_targets:
                break
            
            if total_hours + estimated_hours <= budget_hours:
                selected.append(target)
                total_hours += estimated_hours
            
            # Diversification constraint - max 2 targets per program
            program_count = sum(1 for t in selected if t.program_id == target.program_id)
            if program_count >= 2:
                continue
        
        return selected
    
    async def _calculate_expected_bounty(self, program: 'Program', target: str) -> float:
        """Calculate expected bounty for a target."""
        base_bounty = program.avg_bounty or (program.min_bounty + program.max_bounty) / 2 or 500.0
        
        # Platform multiplier
        platform_multiplier = self.market_factors['platform_multipliers'].get(program.platform, 1.0)
        
        # Target type multiplier
        target_multiplier = 1.0
        if 'api' in target.lower():
            target_multiplier = 1.3
        elif 'admin' in target.lower():
            target_multiplier = 1.4
        elif 'mobile' in target.lower():
            target_multiplier = 1.2
        
        # Company size factor (estimate from bounty range)
        bounty_range = program.max_bounty - program.min_bounty
        size_factor = min(2.0, 1.0 + bounty_range / 10000.0)
        
        expected = base_bounty * platform_multiplier * target_multiplier * size_factor
        return min(expected, program.max_bounty) if program.max_bounty > 0 else expected
    
    async def _analyze_competition(self, program: 'Program') -> float:
        """Analyze competition level for a program."""
        # Factors that increase competition
        competition_score = 0.0
        
        # High max bounty attracts more researchers
        if program.max_bounty > 10000:
            competition_score += 0.3
        elif program.max_bounty > 5000:
            competition_score += 0.2
        elif program.max_bounty > 1000:
            competition_score += 0.1
        
        # High report count indicates active program
        if program.reports_resolved > 1000:
            competition_score += 0.3
        elif program.reports_resolved > 500:
            competition_score += 0.2
        elif program.reports_resolved > 100:
            competition_score += 0.1
        
        # Platform popularity
        platform_competition = {
            'hackerone': 0.4,
            'bugcrowd': 0.3,
            'intigriti': 0.2,
            'yeswehack': 0.15
        }
        competition_score += platform_competition.get(program.platform, 0.2)
        
        # Age of program (newer programs have less competition)
        if program.discovered_at:
            days_old = (datetime.now(timezone.utc) - program.discovered_at).days
            if days_old < 30:
                competition_score -= 0.2
            elif days_old < 90:
                competition_score -= 0.1
        
        return max(0.0, min(1.0, competition_score))
    
    async def _assess_technical_complexity(self, program: 'Program', target: str) -> float:
        """Assess technical complexity of target."""
        complexity = 0.5  # Base complexity
        
        # Scope size increases complexity
        scope_size = len(program.scope or [])
        if scope_size > 20:
            complexity += 0.2
        elif scope_size > 10:
            complexity += 0.1
        
        # Target type complexity
        if 'api' in target.lower():
            complexity += 0.2
        if 'mobile' in target.lower():
            complexity += 0.3
        if 'iot' in target.lower():
            complexity += 0.4
        if any(tech in (program.description or '').lower() 
               for tech in ['blockchain', 'ai', 'ml', 'quantum']):
            complexity += 0.3
        
        # Company type (fintech, healthcare = more complex)
        if any(sector in (program.description or '').lower() 
               for sector in ['bank', 'financial', 'healthcare', 'medical']):
            complexity += 0.2
        
        return max(0.0, min(1.0, complexity))
    
    async def _calculate_success_rate(self, program_id: int) -> float:
        """Calculate historical success rate."""
        try:
            async with get_async_db() as db:
                # Get vulnerability count
                vuln_count = await db.query(Vulnerability).join(Scan).filter(
                    Scan.program_id == program_id,
                    Vulnerability.verified == True
                ).count()
                
                # Get total scan count
                scan_count = await db.query(Scan).filter(
                    Scan.program_id == program_id,
                    Scan.status == 'completed'
                ).count()
                
                if scan_count == 0:
                    return 0.1  # Default low success rate for new programs
                
                return min(1.0, vuln_count / scan_count)
                
        except Exception as e:
            logger.error(f"Failed to calculate success rate: {e}")
            return 0.1
    
    async def _calculate_avg_time_to_bug(self, program_id: int) -> float:
        """Calculate average time to find first bug."""
        try:
            async with get_async_db() as db:
                # Get scans with vulnerabilities
                scans_with_bugs = await db.query(Scan).join(Vulnerability).filter(
                    Scan.program_id == program_id,
                    Scan.status == 'completed'
                ).all()
                
                if not scans_with_bugs:
                    return 24.0  # Default 24 hours
                
                times = [scan.duration / 3600 for scan in scans_with_bugs if scan.duration]
                return np.mean(times) if times else 24.0
                
        except Exception as e:
            logger.error(f"Failed to calculate time to bug: {e}")
            return 24.0
    
    async def _assess_compliance_risk(self, program: 'Program', target: str) -> float:
        """Assess compliance risk for target."""
        risk = 0.0
        
        # Check for high-risk domains
        high_risk_keywords = ['prod', 'production', 'live', 'admin', 'internal']
        if any(keyword in target.lower() for keyword in high_risk_keywords):
            risk += 0.3
        
        # Platform risk
        if program.platform in ['hackerone', 'bugcrowd']:
            risk += 0.1  # Well-established platforms have better compliance
        else:
            risk += 0.2  # Newer platforms may have less clear rules
        
        # Scope clarity
        if not program.scope or len(program.scope) == 0:
            risk += 0.4
        
        return max(0.0, min(1.0, risk))
    
    async def _assess_reputation_risk(self, program: 'Program') -> float:
        """Assess reputation risk."""
        risk = 0.0
        
        # Response time risk
        if program.response_time_avg and program.response_time_avg > 168:  # >1 week
            risk += 0.2
        
        # Low resolution rate
        if program.reports_submitted > 0:
            resolution_rate = program.reports_resolved / program.reports_submitted
            if resolution_rate < 0.3:
                risk += 0.3
        
        return max(0.0, min(1.0, risk))
    
    async def _calculate_roi_score(self, metrics: TargetMetrics) -> float:
        """Calculate overall ROI score."""
        # Expected return
        expected_return = metrics.expected_bounty * metrics.historical_success_rate
        
        # Time investment (inverse relationship)
        time_factor = 1.0 / max(1.0, metrics.time_to_first_bug / 8.0)  # Normalize to 8 hours
        
        # Competition penalty
        competition_penalty = 1.0 - (metrics.competition_level * 0.5)
        
        # Risk penalty
        risk_penalty = 1.0 - ((metrics.compliance_risk + metrics.reputation_risk) * 0.5)
        
        roi_score = expected_return * time_factor * competition_penalty * risk_penalty
        
        return max(0.0, min(100.0, roi_score))
    
    async def _calculate_priority_score(self, metrics: TargetMetrics) -> float:
        """Calculate priority score balancing multiple factors."""
        # Weighted combination of factors
        weights = {
            'roi': 0.4,
            'success_rate': 0.2,
            'bounty': 0.2,
            'competition': -0.1,  # Lower competition is better
            'risk': -0.1  # Lower risk is better
        }
        
        normalized_roi = min(1.0, metrics.roi_score / 100.0)
        normalized_bounty = min(1.0, metrics.expected_bounty / 10000.0)
        
        priority = (
            weights['roi'] * normalized_roi +
            weights['success_rate'] * metrics.historical_success_rate +
            weights['bounty'] * normalized_bounty +
            weights['competition'] * metrics.competition_level +
            weights['risk'] * (metrics.compliance_risk + metrics.reputation_risk) / 2
        )
        
        return max(0.0, min(100.0, priority * 100))
    
    async def _calculate_confidence(self, metrics: TargetMetrics, program: 'Program') -> float:
        """Calculate confidence in the metrics."""
        confidence = 0.5  # Base confidence
        
        # More data = higher confidence
        if program.reports_resolved > 100:
            confidence += 0.2
        elif program.reports_resolved > 20:
            confidence += 0.1
        
        # Established program = higher confidence
        if program.discovered_at:
            days_old = (datetime.now(timezone.utc) - program.discovered_at).days
            if days_old > 365:
                confidence += 0.2
            elif days_old > 90:
                confidence += 0.1
        
        # Clear scope = higher confidence
        if program.scope and len(program.scope) > 0:
            confidence += 0.1
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_confidence_interval(self, targets: List[TargetMetrics]) -> Dict[str, float]:
        """Calculate confidence interval for portfolio metrics."""
        if not targets:
            return {'lower': 0.0, 'upper': 0.0, 'mean': 0.0}
        
        roi_scores = [t.roi_score for t in targets]
        mean_roi = np.mean(roi_scores)
        std_roi = np.std(roi_scores)
        
        # 95% confidence interval
        margin_of_error = 1.96 * (std_roi / np.sqrt(len(targets)))
        
        return {
            'mean': mean_roi,
            'lower': mean_roi - margin_of_error,
            'upper': mean_roi + margin_of_error,
            'std_dev': std_roi
        }

# Global ROI calculator instance
roi_calculator = ROICalculator()