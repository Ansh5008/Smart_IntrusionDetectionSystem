"""
Attack Simulation CLI Tool
Generates and simulates various network attacks for IDS testing
"""

from __future__ import annotations

import argparse
from pathlib import Path
from datetime import datetime
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from simulation.attack_generator import AttackSimulator


def main():
    parser = argparse.ArgumentParser(
        description="Generate attack traffic for IDS testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 500 DDoS attack records
  python simulate_attacks.py --attack ddos --count 500 --output ddos_attack.csv
  
  # Generate port scan with high intensity
  python simulate_attacks.py --attack port-scan --count 200 --intensity 0.9
  
  # Generate web attacks with specific parameters
  python simulate_attacks.py --attack web --count 300 --output web_attacks.csv
  
  # Generate multiple attack types
  python simulate_attacks.py --attack mixed --count 1000
  
  # Generate normal baseline traffic
  python simulate_attacks.py --attack normal --count 500 --output benign.csv
        """
    )
    
    parser.add_argument(
        "--attack",
        choices=["ddos", "port-scan", "web", "exfiltration", "brute-force", "normal", "mixed"],
        default="mixed",
        help="Type of attack to simulate (default: mixed)"
    )
    
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of attack records to generate (default: 100)"
    )
    
    parser.add_argument(
        "--intensity",
        type=float,
        default=0.7,
        choices=[x / 10 for x in range(1, 11)],
        help="Attack intensity from 0.1 to 1.0 (default: 0.7)"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        help="Output CSV file path (default: stdout)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print verbose output"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        print(f"[*] Generating {args.count} {args.attack} attack records...")
        print(f"[*] Attack intensity: {args.intensity}")
        print(f"[*] Timestamp: {datetime.now().isoformat()}")
    
    # Generate attacks based on selection
    if args.attack == "ddos":
        df = AttackSimulator.generate_ddos_attack(count=args.count, intensity=args.intensity)
    elif args.attack == "port-scan":
        df = AttackSimulator.generate_port_scan(count=args.count, intensity=args.intensity)
    elif args.attack == "web":
        df = AttackSimulator.generate_web_attack(count=args.count, intensity=args.intensity)
    elif args.attack == "exfiltration":
        df = AttackSimulator.generate_data_exfiltration(count=args.count, intensity=args.intensity)
    elif args.attack == "brute-force":
        df = AttackSimulator.generate_brute_force(count=args.count, intensity=args.intensity)
    elif args.attack == "normal":
        df = AttackSimulator.generate_normal_traffic(count=args.count)
    else:  # mixed
        # Generate a mix of all attack types
        per_type = args.count // 5
        remainder = args.count % 5
        
        dfs = [
            AttackSimulator.generate_ddos_attack(count=per_type, intensity=args.intensity),
            AttackSimulator.generate_port_scan(count=per_type, intensity=args.intensity),
            AttackSimulator.generate_web_attack(count=per_type, intensity=args.intensity),
            AttackSimulator.generate_data_exfiltration(count=per_type, intensity=args.intensity),
            AttackSimulator.generate_brute_force(count=per_type + remainder, intensity=args.intensity),
        ]
        
        import pandas as pd
        df = pd.concat(dfs, ignore_index=True)
    
    if args.verbose:
        print(f"[+] Generated {len(df)} records")
        print(f"[+] Features: {len(df.columns)}")
        print(f"[+] Attack distribution:")
        for label, count in df['Label'].value_counts().items():
            print(f"    - {label}: {count}")
    
    # Output results
    if args.output:
        df.to_csv(args.output, index=False)
        if args.verbose:
            print(f"[+] Saved to: {args.output.absolute()}")
    else:
        print(df.to_csv(index=False))


if __name__ == "__main__":
    main()
