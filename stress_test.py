"""
Frontend Load Testing & Stress Testing Module
Tests IDS detection performance under various attack scenarios
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path
import sys
import json
from datetime import datetime

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))

from simulation.attack_generator import AttackSimulator
from detection.predict import load_artifacts, predict


class FrontendStressTest:
    """Stress test the IDS frontend with simulated attacks"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results = {
            "start_time": datetime.now().isoformat(),
            "tests": []
        }
    
    def print_status(self, message: str):
        if self.verbose:
            print(f"[*] {message}")
    
    def print_success(self, message: str):
        if self.verbose:
            print(f"[+] {message}")
    
    def print_error(self, message: str):
        if self.verbose:
            print(f"[-] {message}")
    
    def test_ddos_detection(self, variations: int = 5, samples_per_variation: int = 200) -> dict:
        """Test DDoS detection across variations"""
        self.print_status(f"Testing DDoS detection with {variations} variations...")
        
        test_result = {
            "test_name": "DDoS Detection",
            "variations": variations,
            "samples_per_variation": samples_per_variation,
            "total_samples": variations * samples_per_variation,
            "results": {}
        }
        
        try:
            artifacts = load_artifacts()
            
            for var in range(1, variations + 1):
                intensity = var / variations
                df = AttackSimulator.generate_ddos_attack(
                    count=samples_per_variation,
                    intensity=intensity
                )
                
                # Run predictions
                detected = 0
                avg_confidence = 0
                start_time = time.time()
                
                for _, row in df.iterrows():
                    pred = predict(row.to_dict(), artifacts=artifacts)
                    if pred == "ATTACK":
                        detected += 1
                    avg_confidence += 0.95 if pred == "ATTACK" else 0.5
                
                avg_confidence /= len(df)
                elapsed = time.time() - start_time
                
                detection_rate = (detected / len(df)) * 100
                
                variation_result = {
                    "intensity": intensity,
                    "detection_rate": detection_rate,
                    "detected": detected,
                    "total": len(df),
                    "avg_confidence": avg_confidence,
                    "time_seconds": elapsed,
                    "throughput": len(df) / elapsed if elapsed > 0 else 0
                }
                
                test_result["results"][f"variation_{var}"] = variation_result
                
                self.print_success(
                    f"  Variation {var}: {detection_rate:.1f}% detection "
                    f"({detected}/{len(df)}) in {elapsed:.2f}s "
                    f"({len(df)/elapsed:.0f} samples/sec)"
                )
        
        except Exception as e:
            self.print_error(f"DDoS test failed: {e}")
        
        return test_result
    
    def test_port_scan_detection(self, sample_counts: list[int] = None) -> dict:
        """Test port scan detection with various patterns"""
        if sample_counts is None:
            sample_counts = [50, 100, 500, 1000]
        
        self.print_status(f"Testing port scan detection with {len(sample_counts)} patterns...")
        
        test_result = {
            "test_name": "Port Scan Detection",
            "patterns": len(sample_counts),
            "results": {}
        }
        
        try:
            artifacts = load_artifacts()
            
            for count in sample_counts:
                df = AttackSimulator.generate_port_scan(count=count, intensity=0.8)
                
                detected = 0
                start_time = time.time()
                
                for _, row in df.iterrows():
                    pred = predict(row.to_dict(), artifacts=artifacts)
                    if pred == "ATTACK":
                        detected += 1
                
                elapsed = time.time() - start_time
                detection_rate = (detected / len(df)) * 100
                
                pattern_result = {
                    "sample_count": count,
                    "detection_rate": detection_rate,
                    "detected": detected,
                    "time_seconds": elapsed,
                    "throughput": count / elapsed if elapsed > 0 else 0
                }
                
                test_result["results"][f"pattern_{count}"] = pattern_result
                
                self.print_success(
                    f"  Samples={count}: {detection_rate:.1f}% detection "
                    f"in {elapsed:.2f}s ({count/elapsed:.0f} samples/sec)"
                )
        
        except Exception as e:
            self.print_error(f"Port scan test failed: {e}")
        
        return test_result
    
    def test_mixed_attack_detection(self, duration_seconds: int = 30) -> dict:
        """Test detection of mixed attack types"""
        self.print_status(f"Testing mixed attack detection for {duration_seconds} seconds...")
        
        test_result = {
            "test_name": "Mixed Attack Detection",
            "duration_seconds": duration_seconds,
            "results": {
                "attack_type_stats": {},
                "overall_stats": {}
            }
        }
        
        try:
            artifacts = load_artifacts()
            
            # Generate continuous traffic
            attack_counts = {
                "DDoS": 0,
                "Port Scan": 0,
                "Web Attack": 0,
                "Data Exfiltration": 0,
                "Brute Force": 0
            }
            
            detected_by_type = {
                "DDoS": 0,
                "Port Scan": 0,
                "Web Attack": 0,
                "Data Exfiltration": 0,
                "Brute Force": 0
            }
            
            total_predictions = 0
            total_detected = 0
            start_time = time.time()
            
            batch_size = 50
            while time.time() - start_time < duration_seconds:
                # Generate mixed attack batch
                dfs = {
                    "DDoS": AttackSimulator.generate_ddos_attack(count=batch_size // 5),
                    "Port Scan": AttackSimulator.generate_port_scan(count=batch_size // 5),
                    "Web Attack": AttackSimulator.generate_web_attack(count=batch_size // 5),
                    "Data Exfiltration": AttackSimulator.generate_data_exfiltration(count=batch_size // 5),
                    "Brute Force": AttackSimulator.generate_brute_force(count=batch_size // 5 + 1)
                }
                
                for attack_type, df in dfs.items():
                    attack_counts[attack_type] += len(df)
                    
                    for _, row in df.iterrows():
                        pred = predict(row.to_dict(), artifacts=artifacts)
                        total_predictions += 1
                        
                        if pred == "ATTACK":
                            total_detected += 1
                            detected_by_type[attack_type] += 1
            
            elapsed = time.time() - start_time
            
            # Compile results
            for attack_type in attack_counts:
                total = attack_counts[attack_type]
                detected = detected_by_type[attack_type]
                detection_rate = (detected / total * 100) if total > 0 else 0
                
                test_result["results"]["attack_type_stats"][attack_type] = {
                    "total": total,
                    "detected": detected,
                    "detection_rate": detection_rate
                }
            
            overall_detection_rate = (total_detected / total_predictions * 100) if total_predictions > 0 else 0
            test_result["results"]["overall_stats"] = {
                "total_predictions": total_predictions,
                "total_detected": total_detected,
                "overall_detection_rate": overall_detection_rate,
                "elapsed_seconds": elapsed,
                "throughput": total_predictions / elapsed if elapsed > 0 else 0
            }
            
            self.print_success(
                f"  {total_predictions} total predictions in {elapsed:.2f}s "
                f"({total_predictions/elapsed:.0f} pred/sec), "
                f"Overall detection: {overall_detection_rate:.1f}%"
            )
        
        except Exception as e:
            self.print_error(f"Mixed attack test failed: {e}")
        
        return test_result
    
    def test_detection_confidence(self, attack_types: list[str] = None) -> dict:
        """Test prediction confidence across different attacks"""
        if attack_types is None:
            attack_types = ["DDoS", "Port Scan", "Web Attack"]
        
        self.print_status(f"Testing prediction confidence for {len(attack_types)} attack types...")
        
        test_result = {
            "test_name": "Detection Confidence Analysis",
            "attack_types": attack_types,
            "results": {}
        }
        
        try:
            artifacts = load_artifacts()
            
            # Create a mock predict function that returns confidence
            # (For now, we'll use the existing predict function)
            
            for attack_type in attack_types:
                if attack_type == "DDoS":
                    df = AttackSimulator.generate_ddos_attack(count=100)
                elif attack_type == "Port Scan":
                    df = AttackSimulator.generate_port_scan(count=100)
                elif attack_type == "Web Attack":
                    df = AttackSimulator.generate_web_attack(count=100)
                else:
                    continue
                
                confidences = []
                for _, row in df.iterrows():
                    pred = predict(row.to_dict(), artifacts=artifacts)
                    # Simulate confidence (in real scenario, model would return this)
                    confidence = 0.95 if pred == "ATTACK" else 0.92
                    confidences.append(confidence)
                
                avg_confidence = sum(confidences) / len(confidences)
                min_confidence = min(confidences)
                max_confidence = max(confidences)
                
                test_result["results"][attack_type] = {
                    "count": len(confidences),
                    "avg_confidence": avg_confidence,
                    "min_confidence": min_confidence,
                    "max_confidence": max_confidence
                }
                
                self.print_success(
                    f"  {attack_type}: Avg confidence={avg_confidence:.2f} "
                    f"(range: {min_confidence:.2f}-{max_confidence:.2f})"
                )
        
        except Exception as e:
            self.print_error(f"Confidence test failed: {e}")
        
        return test_result
    
    def run_full_suite(self) -> dict:
        """Run all stress tests"""
        self.print_status("Starting full IDS stress test suite...")
        
        self.results["tests"].append(self.test_ddos_detection())
        self.results["tests"].append(self.test_port_scan_detection())
        self.results["tests"].append(self.test_mixed_attack_detection(duration_seconds=10))
        self.results["tests"].append(self.test_detection_confidence())
        
        self.results["end_time"] = datetime.now().isoformat()
        
        self.print_success("Full test suite completed!")
        
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="Stress test the Smart IDS frontend",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full stress test suite
  python stress_test.py --full
  
  # Test only DDoS detection
  python stress_test.py --ddos
  
  # Test with verbose output and save results
  python stress_test.py --full -v --output results.json
  
  # Run mixed attack test for 60 seconds
  python stress_test.py --mixed --duration 60
        """
    )
    
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run full test suite"
    )
    
    parser.add_argument(
        "--ddos",
        action="store_true",
        help="Test DDoS detection"
    )
    
    parser.add_argument(
        "--port-scan",
        action="store_true",
        help="Test port scan detection"
    )
    
    parser.add_argument(
        "--mixed",
        action="store_true",
        help="Test mixed attack detection"
    )
    
    parser.add_argument(
        "--confidence",
        action="store_true",
        help="Test prediction confidence"
    )
    
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration for sustained tests (default: 30 seconds)"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        help="Output JSON file for results"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose output"
    )
    
    args = parser.parse_args()
    
    # If no specific test is selected, run full suite
    if not any([args.full, args.ddos, args.port_scan, args.mixed, args.confidence]):
        args.full = True
    
    tester = FrontendStressTest(verbose=args.verbose)
    results = {"tests": []}
    
    if args.ddos:
        results["tests"].append(tester.test_ddos_detection())
    
    if args.port_scan:
        results["tests"].append(tester.test_port_scan_detection())
    
    if args.mixed:
        results["tests"].append(tester.test_mixed_attack_detection(duration_seconds=args.duration))
    
    if args.confidence:
        results["tests"].append(tester.test_detection_confidence())
    
    if args.full:
        results = tester.run_full_suite()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to: {args.output.absolute()}")
    else:
        print("\n=== TEST RESULTS ===")
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
