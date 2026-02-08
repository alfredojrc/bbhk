"""ML-based success prediction and recommendation engine."""

import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sklearn.ensemble import RandomForestClassifier, GradientBoostingRegressor
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score
from loguru import logger

from ..core.database import Program, Vulnerability, Scan, get_async_db
from ..core.config import config

class SuccessPredictor:
    """ML-based predictor for bug bounty success."""
    
    def __init__(self):
        """Initialize success predictor."""
        self.success_model = None
        self.bounty_model = None
        self.time_model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        
        self.feature_columns = [
            'program_age_days', 'max_bounty', 'avg_bounty', 'reports_resolved',
            'scope_size', 'platform_encoded', 'competition_level', 'target_type_encoded',
            'technical_complexity', 'response_time', 'resolution_rate'
        ]
    
    async def train_models(self):
        """Train ML models on historical data."""
        try:
            logger.info("Training ML models for success prediction")
            
            # Prepare training data
            training_data = await self._prepare_training_data()
            
            if len(training_data) < 100:
                logger.warning(f"Insufficient training data ({len(training_data)} samples). Using baseline models.")
                self._create_baseline_models()
                return
            
            # Split features and targets
            features = training_data[self.feature_columns]
            success_target = training_data['found_vulnerability']
            bounty_target = training_data['actual_bounty']
            time_target = training_data['time_to_bug']
            
            # Scale features
            features_scaled = self.scaler.fit_transform(features)
            
            # Train success prediction model
            await self._train_success_model(features_scaled, success_target)
            
            # Train bounty prediction model
            await self._train_bounty_model(features_scaled, bounty_target)
            
            # Train time prediction model
            await self._train_time_model(features_scaled, time_target)
            
            # Save models
            await self._save_models()
            
            logger.info("ML models trained successfully")
            
        except Exception as e:
            logger.error(f"Failed to train ML models: {e}")
            self._create_baseline_models()
    
    async def predict_success_probability(self, program_id: int, target: str) -> float:
        """Predict probability of finding vulnerabilities."""
        try:
            if not self.success_model:
                await self.load_models()
            
            features = await self._extract_features(program_id, target)
            features_scaled = self.scaler.transform([features])
            
            if hasattr(self.success_model, 'predict_proba'):
                probability = self.success_model.predict_proba(features_scaled)[0][1]
            else:
                probability = max(0.0, min(1.0, self.success_model.predict(features_scaled)[0]))
            
            return probability
            
        except Exception as e:
            logger.error(f"Failed to predict success probability: {e}")
            return 0.3  # Conservative default
    
    async def predict_bounty_range(self, program_id: int, target: str) -> Tuple[float, float]:
        """Predict expected bounty range."""
        try:
            if not self.bounty_model:
                await self.load_models()
            
            features = await self._extract_features(program_id, target)
            features_scaled = self.scaler.transform([features])
            
            predicted_bounty = max(0.0, self.bounty_model.predict(features_scaled)[0])
            
            # Calculate confidence interval (rough estimate)
            std_factor = 0.5  # Assume 50% standard deviation
            lower_bound = predicted_bounty * (1 - std_factor)
            upper_bound = predicted_bounty * (1 + std_factor)
            
            return lower_bound, upper_bound
            
        except Exception as e:
            logger.error(f"Failed to predict bounty range: {e}")
            return 100.0, 1000.0  # Default range
    
    async def predict_time_to_bug(self, program_id: int, target: str) -> float:
        """Predict expected time to find first bug (hours)."""
        try:
            if not self.time_model:
                await self.load_models()
            
            features = await self._extract_features(program_id, target)
            features_scaled = self.scaler.transform([features])
            
            predicted_hours = max(1.0, self.time_model.predict(features_scaled)[0])
            
            return predicted_hours
            
        except Exception as e:
            logger.error(f"Failed to predict time to bug: {e}")
            return 24.0  # Default 24 hours
    
    async def get_recommendations(self, program_id: int, target: str) -> Dict[str, Any]:
        """Get comprehensive recommendations for a target."""
        try:
            success_prob = await self.predict_success_probability(program_id, target)
            bounty_range = await self.predict_bounty_range(program_id, target)
            time_estimate = await self.predict_time_to_bug(program_id, target)
            
            # Calculate expected value
            expected_value = success_prob * (bounty_range[0] + bounty_range[1]) / 2
            
            # Get strategic recommendations
            recommendations = await self._generate_strategic_recommendations(
                program_id, target, success_prob, bounty_range, time_estimate
            )
            
            return {
                'success_probability': success_prob,
                'expected_bounty_range': bounty_range,
                'estimated_time_hours': time_estimate,
                'expected_value': expected_value,
                'recommendations': recommendations,
                'confidence': await self._calculate_prediction_confidence(program_id)
            }
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}")
            return {
                'success_probability': 0.3,
                'expected_bounty_range': (100.0, 1000.0),
                'estimated_time_hours': 24.0,
                'expected_value': 300.0,
                'recommendations': ['Insufficient data for detailed recommendations'],
                'confidence': 0.3
            }
    
    async def _prepare_training_data(self) -> pd.DataFrame:
        """Prepare training data from historical scans."""
        training_data = []
        
        async with get_async_db() as db:
            # Get completed scans with known outcomes
            scans = await db.query(Scan).filter(
                Scan.status == 'completed'
            ).all()
            
            for scan in scans:
                try:
                    program = await db.get(Program, scan.program_id)
                    if not program:
                        continue
                    
                    # Get vulnerabilities for this scan
                    vulnerabilities = await db.query(Vulnerability).filter(
                        Vulnerability.scan_id == scan.id,
                        Vulnerability.verified == True
                    ).all()
                    
                    # Extract features
                    features = await self._extract_features_for_program(program, scan.target)
                    
                    # Extract targets
                    found_vuln = len(vulnerabilities) > 0
                    actual_bounty = sum(v.cvss_score * 100 for v in vulnerabilities) if vulnerabilities else 0.0
                    time_to_bug = scan.duration / 3600 if scan.duration else 24.0
                    
                    # Create training sample
                    sample = {
                        **features,
                        'found_vulnerability': 1 if found_vuln else 0,
                        'actual_bounty': actual_bounty,
                        'time_to_bug': time_to_bug
                    }
                    
                    training_data.append(sample)
                    
                except Exception as e:
                    logger.debug(f"Failed to process scan {scan.id}: {e}")
        
        return pd.DataFrame(training_data)
    
    async def _extract_features(self, program_id: int, target: str) -> List[float]:
        """Extract features for a specific target."""
        async with get_async_db() as db:
            program = await db.get(Program, program_id)
            if not program:
                raise ValueError(f"Program {program_id} not found")
            
            return await self._extract_features_for_program(program, target)
    
    async def _extract_features_for_program(self, program, target: str) -> Dict[str, float]:
        """Extract features from program and target."""
        # Calculate program age
        if program.discovered_at:
            age_days = (datetime.now(timezone.utc) - program.discovered_at).days
        else:
            age_days = 0
        
        # Calculate resolution rate
        resolution_rate = 0.0
        if program.reports_submitted > 0:
            resolution_rate = program.reports_resolved / program.reports_submitted
        
        # Encode categorical variables
        platform_encoded = self._encode_categorical('platform', program.platform)
        target_type_encoded = self._encode_categorical('target_type', self._classify_target_type(target))
        
        # Estimate competition and complexity
        competition_level = await self._estimate_competition(program)
        technical_complexity = await self._estimate_complexity(program, target)
        
        features = {
            'program_age_days': age_days,
            'max_bounty': program.max_bounty or 0.0,
            'avg_bounty': program.avg_bounty or 0.0,
            'reports_resolved': program.reports_resolved or 0,
            'scope_size': len(program.scope or []),
            'platform_encoded': platform_encoded,
            'competition_level': competition_level,
            'target_type_encoded': target_type_encoded,
            'technical_complexity': technical_complexity,
            'response_time': program.response_time_avg or 72.0,
            'resolution_rate': resolution_rate
        }
        
        return features
    
    def _classify_target_type(self, target: str) -> str:
        """Classify target type from URL/target string."""
        target_lower = target.lower()
        
        if 'api' in target_lower:
            return 'api'
        elif 'mobile' in target_lower or 'app' in target_lower:
            return 'mobile'
        elif 'admin' in target_lower:
            return 'admin'
        elif 'test' in target_lower or 'stage' in target_lower:
            return 'staging'
        else:
            return 'web'
    
    def _encode_categorical(self, feature_name: str, value: str) -> float:
        """Encode categorical variable."""
        if feature_name not in self.label_encoders:
            self.label_encoders[feature_name] = LabelEncoder()
            # Pre-fit with known values
            if feature_name == 'platform':
                self.label_encoders[feature_name].fit(['hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'other'])
            elif feature_name == 'target_type':
                self.label_encoders[feature_name].fit(['web', 'api', 'mobile', 'admin', 'staging', 'other'])
        
        try:
            return float(self.label_encoders[feature_name].transform([value])[0])
        except (ValueError, KeyError):
            # Unknown category
            return 0.0
    
    async def _estimate_competition(self, program) -> float:
        """Estimate competition level for program."""
        competition = 0.0
        
        # High bounty = more competition
        if program.max_bounty > 10000:
            competition += 0.4
        elif program.max_bounty > 5000:
            competition += 0.3
        elif program.max_bounty > 1000:
            competition += 0.2
        
        # High report count = established program = more competition
        if program.reports_resolved > 1000:
            competition += 0.3
        elif program.reports_resolved > 500:
            competition += 0.2
        elif program.reports_resolved > 100:
            competition += 0.1
        
        return min(1.0, competition)
    
    async def _estimate_complexity(self, program, target: str) -> float:
        """Estimate technical complexity."""
        complexity = 0.5  # Base complexity
        
        # Target-based complexity
        if 'api' in target.lower():
            complexity += 0.2
        if 'mobile' in target.lower():
            complexity += 0.3
        
        # Program description complexity indicators
        description = (program.description or '').lower()
        complex_tech = ['blockchain', 'ai', 'ml', 'iot', 'quantum', 'crypto']
        for tech in complex_tech:
            if tech in description:
                complexity += 0.1
        
        return min(1.0, complexity)
    
    async def _train_success_model(self, features: np.ndarray, targets: np.ndarray):
        """Train success prediction model."""
        X_train, X_test, y_train, y_test = train_test_split(
            features, targets, test_size=0.2, random_state=42
        )
        
        self.success_model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=10, 
            random_state=42
        )
        
        self.success_model.fit(X_train, y_train)
        
        # Log performance
        y_pred = self.success_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, average='weighted')
        
        logger.info(f"Success model - Accuracy: {accuracy:.3f}, Precision: {precision:.3f}")
    
    async def _train_bounty_model(self, features: np.ndarray, targets: np.ndarray):
        """Train bounty prediction model."""
        # Filter out zero bounties for training
        non_zero_mask = targets > 0
        if np.sum(non_zero_mask) < 10:
            logger.warning("Insufficient non-zero bounty data")
            self.bounty_model = lambda x: np.array([500.0] * len(x))  # Default predictor
            return
        
        features_filtered = features[non_zero_mask]
        targets_filtered = targets[non_zero_mask]
        
        X_train, X_test, y_train, y_test = train_test_split(
            features_filtered, targets_filtered, test_size=0.2, random_state=42
        )
        
        self.bounty_model = GradientBoostingRegressor(
            n_estimators=100, 
            max_depth=6, 
            learning_rate=0.1,
            random_state=42
        )
        
        self.bounty_model.fit(X_train, y_train)
        
        # Log performance
        score = self.bounty_model.score(X_test, y_test)
        logger.info(f"Bounty model - R² Score: {score:.3f}")
    
    async def _train_time_model(self, features: np.ndarray, targets: np.ndarray):
        """Train time prediction model."""
        X_train, X_test, y_train, y_test = train_test_split(
            features, targets, test_size=0.2, random_state=42
        )
        
        self.time_model = GradientBoostingRegressor(
            n_estimators=100, 
            max_depth=6, 
            learning_rate=0.1,
            random_state=42
        )
        
        self.time_model.fit(X_train, y_train)
        
        # Log performance
        score = self.time_model.score(X_test, y_test)
        logger.info(f"Time model - R² Score: {score:.3f}")
    
    def _create_baseline_models(self):
        """Create simple baseline models when insufficient data."""
        logger.info("Creating baseline prediction models")
        
        # Simple rule-based models
        self.success_model = lambda x: np.array([0.3] * len(x))  # 30% baseline success rate
        self.bounty_model = lambda x: np.array([500.0] * len(x))  # $500 baseline bounty
        self.time_model = lambda x: np.array([24.0] * len(x))  # 24 hours baseline time
    
    async def _save_models(self):
        """Save trained models to disk."""
        try:
            model_dir = config.analytics.ml_model_path
            import os
            os.makedirs(model_dir, exist_ok=True)
            
            with open(f"{model_dir}/success_model.pkl", 'wb') as f:
                pickle.dump(self.success_model, f)
            
            with open(f"{model_dir}/bounty_model.pkl", 'wb') as f:
                pickle.dump(self.bounty_model, f)
            
            with open(f"{model_dir}/time_model.pkl", 'wb') as f:
                pickle.dump(self.time_model, f)
            
            with open(f"{model_dir}/scaler.pkl", 'wb') as f:
                pickle.dump(self.scaler, f)
            
            with open(f"{model_dir}/encoders.pkl", 'wb') as f:
                pickle.dump(self.label_encoders, f)
            
            logger.info("Models saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
    
    async def load_models(self):
        """Load trained models from disk."""
        try:
            model_dir = config.analytics.ml_model_path
            
            with open(f"{model_dir}/success_model.pkl", 'rb') as f:
                self.success_model = pickle.load(f)
            
            with open(f"{model_dir}/bounty_model.pkl", 'rb') as f:
                self.bounty_model = pickle.load(f)
            
            with open(f"{model_dir}/time_model.pkl", 'rb') as f:
                self.time_model = pickle.load(f)
            
            with open(f"{model_dir}/scaler.pkl", 'rb') as f:
                self.scaler = pickle.load(f)
            
            with open(f"{model_dir}/encoders.pkl", 'rb') as f:
                self.label_encoders = pickle.load(f)
            
            logger.info("Models loaded successfully")
            
        except FileNotFoundError:
            logger.warning("No saved models found, creating baseline models")
            self._create_baseline_models()
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            self._create_baseline_models()
    
    async def _generate_strategic_recommendations(self, program_id: int, target: str, 
                                                success_prob: float, bounty_range: Tuple[float, float], 
                                                time_estimate: float) -> List[str]:
        """Generate strategic recommendations based on predictions."""
        recommendations = []
        
        # Success probability recommendations
        if success_prob > 0.7:
            recommendations.append("High success probability - prioritize this target")
        elif success_prob < 0.2:
            recommendations.append("Low success probability - consider alternative targets")
        
        # Bounty recommendations
        avg_bounty = (bounty_range[0] + bounty_range[1]) / 2
        if avg_bounty > 5000:
            recommendations.append("High bounty potential - worth significant time investment")
        elif avg_bounty < 500:
            recommendations.append("Lower bounty range - focus on quick wins")
        
        # Time recommendations
        if time_estimate < 8:
            recommendations.append("Quick turnaround expected - good for immediate results")
        elif time_estimate > 40:
            recommendations.append("Extended time investment needed - plan accordingly")
        
        # Target-specific recommendations
        if 'api' in target.lower():
            recommendations.append("API target - focus on authentication and input validation")
        elif 'admin' in target.lower():
            recommendations.append("Admin interface - look for privilege escalation and access controls")
        
        return recommendations
    
    async def _calculate_prediction_confidence(self, program_id: int) -> float:
        """Calculate confidence in predictions based on data availability."""
        try:
            async with get_async_db() as db:
                program = await db.get(Program, program_id)
                if not program:
                    return 0.3
                
                confidence = 0.3  # Base confidence
                
                # More historical data = higher confidence
                if program.reports_resolved > 100:
                    confidence += 0.3
                elif program.reports_resolved > 20:
                    confidence += 0.2
                elif program.reports_resolved > 5:
                    confidence += 0.1
                
                # Established program = higher confidence
                if program.discovered_at:
                    days_old = (datetime.now(timezone.utc) - program.discovered_at).days
                    if days_old > 365:
                        confidence += 0.2
                    elif days_old > 180:
                        confidence += 0.1
                
                return min(1.0, confidence)
                
        except Exception as e:
            logger.error(f"Failed to calculate prediction confidence: {e}")
            return 0.3

# Global predictor instance
success_predictor = SuccessPredictor()