"""
Feedback loop infrastructure for model improvement.
Tracks false positives, missed fraud, and rule effectiveness.
"""

from datetime import datetime
from fraud_detection.utils import get_db

def log_feedback(transaction_id: str, case_id: str = '', feedback_type: str = '', 
                 ground_truth: str = '', system_decision: str = '', 
                 rule_triggered: str = '', confidence_score: float = 0.0,
                 analyst_notes: str = '') -> bool:
    """
    Log feedback for a transaction decision.
    Enables tracking of false positives, missed fraud, and decision accuracy.
    
    Args:
        transaction_id: Transaction identifier
        case_id: Case identifier (if case was created)
        feedback_type: 'false_positive', 'missed_fraud', 'correct_accept', 'correct_deny'
        ground_truth: Actual outcome ('fraud', 'legitimate', 'unknown')
        system_decision: System's disposition ('accept', 'deny', 'review')
        rule_triggered: Rule that triggered the flag (from KNOWN_RULE_NAMES)
        confidence_score: Model's confidence in the decision (0-1)
        analyst_notes: Notes from analyst
    
    Returns:
        Boolean indicating success
    """
    db = get_db()
    cur = db.cursor()
    
    try:
        # Determine if prediction was correct
        correct_prediction = None
        if feedback_type == 'false_positive':
            correct_prediction = 0
        elif feedback_type == 'missed_fraud':
            correct_prediction = 0
        elif feedback_type == 'correct_accept':
            correct_prediction = 1
        elif feedback_type == 'correct_deny':
            correct_prediction = 1
        
        cur.execute("""
            INSERT INTO feedback_log
            (transaction_id, case_id, feedback_type, ground_truth, system_decision,
             rule_triggered, confidence_score, analyst_notes, correct_prediction, feedback_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())
        """, (
            transaction_id, case_id, feedback_type, ground_truth, system_decision,
            rule_triggered, confidence_score, analyst_notes, correct_prediction
        ))
        
        db.commit()
        return True
    except Exception as e:
        print(f"Error logging feedback: {e}")
        return False
    finally:
        cur.close()
        db.close()

def get_rule_effectiveness() -> dict:
    """
    Analyze rule effectiveness from feedback.
    Calculates precision, recall, and F1 for each rule.
    
    Returns:
        Dict with rule statistics:
        {
            'rule_name': {
                'total_triggers': int,
                'correct': int,
                'false_positives': int,
                'missed_fraud': int,
                'precision': float,
                'recall': float,
                'f1_score': float
            }
        }
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        # Get all feedback grouped by rule
        cur.execute("""
            SELECT rule_triggered, COUNT(*) as total,
                   SUM(CASE WHEN correct_prediction=1 THEN 1 ELSE 0 END) as correct,
                   SUM(CASE WHEN feedback_type='false_positive' THEN 1 ELSE 0 END) as fp,
                   SUM(CASE WHEN feedback_type='missed_fraud' THEN 1 ELSE 0 END) as fn
            FROM feedback_log
            WHERE rule_triggered IS NOT NULL AND rule_triggered != ''
            GROUP BY rule_triggered
            ORDER BY total DESC
        """)
        
        results = cur.fetchall()
        effectiveness = {}
        
        for row in results:
            rule = row['rule_triggered']
            total = row['total']
            correct = row['correct'] or 0
            fp = row['fp'] or 0
            fn = row['fn'] or 0
            
            # Calculate metrics
            precision = correct / (correct + fp) if (correct + fp) > 0 else 0.0
            recall = correct / (correct + fn) if (correct + fn) > 0 else 0.0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
            
            effectiveness[rule] = {
                'total_triggers': total,
                'correct': correct,
                'false_positives': fp,
                'missed_fraud': fn,
                'precision': round(precision, 4),
                'recall': round(recall, 4),
                'f1_score': round(f1, 4)
            }
        
        return effectiveness
    finally:
        cur.close()
        db.close()

def get_model_performance_metrics(lookback_days: int = 30) -> dict:
    """
    Compute overall model performance metrics over recent period.
    
    Returns:
        Dict with metrics:
        - total_feedback: Number of feedback records
        - accuracy: Fraction correct
        - false_positive_rate: Fraction of denies that were incorrect
        - missed_fraud_rate: Fraction of accepts that should have been denies
        - precision: TP / (TP + FP)
        - recall: TP / (TP + FN)
        - f1_score: Harmonic mean
    """
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        lookback_date = f"DATE_SUB(NOW(), INTERVAL {lookback_days} DAY)"
        
        cur.execute(f"""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN correct_prediction=1 THEN 1 ELSE 0 END) as correct,
                SUM(CASE WHEN feedback_type='false_positive' THEN 1 ELSE 0 END) as fp,
                SUM(CASE WHEN feedback_type='missed_fraud' THEN 1 ELSE 0 END) as fn,
                SUM(CASE WHEN feedback_type='correct_deny' THEN 1 ELSE 0 END) as tp,
                SUM(CASE WHEN feedback_type='correct_accept' THEN 1 ELSE 0 END) as tn
            FROM feedback_log
            WHERE feedback_at >= {lookback_date}
        """)
        
        result = cur.fetchone()
        
        metrics = {
            'lookback_days': lookback_days,
            'total_feedback': result['total'] or 0,
            'accuracy': 0.0,
            'false_positive_rate': 0.0,
            'missed_fraud_rate': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1_score': 0.0
        }
        
        if metrics['total_feedback'] == 0:
            return metrics
        
        correct = result['correct'] or 0
        fp = result['fp'] or 0
        fn = result['fn'] or 0
        tp = result['tp'] or 0
        tn = result['tn'] or 0
        
        # Calculate metrics
        metrics['accuracy'] = round(correct / metrics['total_feedback'], 4)
        metrics['false_positive_rate'] = round(fp / (fp + tn) if (fp + tn) > 0 else 0, 4)
        metrics['missed_fraud_rate'] = round(fn / (fn + tp) if (fn + tp) > 0 else 0, 4)
        metrics['precision'] = round(tp / (tp + fp) if (tp + fp) > 0 else 0, 4)
        metrics['recall'] = round(tp / (tp + fn) if (tp + fn) > 0 else 0, 4)
        
        if (metrics['precision'] + metrics['recall']) > 0:
            metrics['f1_score'] = round(
                2 * (metrics['precision'] * metrics['recall']) / 
                (metrics['precision'] + metrics['recall']), 4
            )
        
        return metrics
    finally:
        cur.close()
        db.close()

def get_feedback_summary(transaction_id: str) -> dict:
    """Get all feedback entries for a specific transaction."""
    db = get_db()
    cur = db.cursor(dictionary=True)
    
    try:
        cur.execute("""
            SELECT * FROM feedback_log
            WHERE transaction_id = %s
            ORDER BY feedback_at DESC
        """, (transaction_id,))
        
        feedbacks = cur.fetchall()
        return {
            'transaction_id': transaction_id,
            'feedback_count': len(feedbacks),
            'feedbacks': feedbacks
        }
    finally:
        cur.close()
        db.close()

def identify_high_false_positive_rules(threshold: float = 0.3, min_triggers: int = 10) -> list:
    """
    Identify rules that have high false positive rates.
    These rules may need adjustment or removal.
    
    Args:
        threshold: FP rate threshold (e.g., 0.3 = 30%)
        min_triggers: Minimum number of triggers to consider
    
    Returns:
        List of rule names with high FP rates
    """
    effectiveness = get_rule_effectiveness()
    problematic_rules = []
    
    for rule, stats in effectiveness.items():
        if stats['total_triggers'] >= min_triggers:
            fp_rate = stats['false_positives'] / stats['total_triggers']
            if fp_rate > threshold:
                problematic_rules.append({
                    'rule': rule,
                    'fp_rate': round(fp_rate, 4),
                    'total_triggers': stats['total_triggers'],
                    'false_positives': stats['false_positives']
                })
    
    return sorted(problematic_rules, key=lambda x: x['fp_rate'], reverse=True)
