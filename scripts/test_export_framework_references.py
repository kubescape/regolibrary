#!/usr/bin/env python3
"""
Test to validate that framework references are correctly added to controls
"""
import json
import os
import sys
import tempfile
import subprocess

def test_framework_references():
    """Test that controls have framework references after export"""
    
    # Save original directory
    original_dir = os.getcwd()
    
    try:
        # Change to repository root
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        os.chdir(repo_root)
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Run export.py script
            env = os.environ.copy()
            env['OUTPUT'] = temp_dir
            env['RELEASE'] = 'test'
            
            result = subprocess.run(
                [sys.executable, 'scripts/export.py'],
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                print(f"ERROR: export.py failed with return code {result.returncode}")
                print(f"STDOUT: {result.stdout}")
                print(f"STDERR: {result.stderr}")
                return False
            
            # Read the generated controls.json
            controls_path = os.path.join(temp_dir, 'controls.json')
            with open(controls_path, 'r') as f:
                controls = json.load(f)
            
            # Validate that all controls have the frameworks field
            controls_without_frameworks_field = []
            for control in controls:
                if 'frameworks' not in control:
                    controls_without_frameworks_field.append(control.get('controlID', 'Unknown'))
            
            if controls_without_frameworks_field:
                print(f"ERROR: {len(controls_without_frameworks_field)} controls missing 'frameworks' field:")
                for control_id in controls_without_frameworks_field[:10]:  # Show first 10
                    print(f"  - {control_id}")
                return False
            
            # Validate that the frameworks field is a list
            controls_with_invalid_frameworks = []
            for control in controls:
                if not isinstance(control.get('frameworks'), list):
                    controls_with_invalid_frameworks.append(control.get('controlID', 'Unknown'))
            
            if controls_with_invalid_frameworks:
                print(f"ERROR: {len(controls_with_invalid_frameworks)} controls have invalid 'frameworks' field:")
                for control_id in controls_with_invalid_frameworks[:10]:
                    print(f"  - {control_id}")
                return False
            
            # Validate specific known controls
            test_cases = {
                'C-0056': ['AllControls', 'DevOpsBest'],  # Should be in DevOpsBest
                'C-0284': ['cis-v1.10.0'],  # CIS control
                'C-0034': ['AllControls', 'ArmoBest', 'NSA', 'WorkloadScan', 'security'],  # Multiple frameworks
            }
            
            for control_id, expected_frameworks in test_cases.items():
                control = next((c for c in controls if c['controlID'] == control_id), None)
                if not control:
                    print(f"ERROR: Test control {control_id} not found")
                    return False
                
                actual_frameworks = set(control['frameworks'])
                expected_set = set(expected_frameworks)
                
                if not expected_set.issubset(actual_frameworks):
                    missing = expected_set - actual_frameworks
                    print(f"ERROR: Control {control_id} missing expected frameworks: {missing}")
                    print(f"  Expected (at least): {expected_frameworks}")
                    print(f"  Actual: {sorted(control['frameworks'])}")
                    return False
            
            # Read the CSV to validate it still exists and works
            csv_path = os.path.join(temp_dir, 'FWName_CID_CName.csv')
            if not os.path.exists(csv_path):
                print("ERROR: FWName_CID_CName.csv was not generated")
                return False
            
            print("✓ All controls have 'frameworks' field")
            print("✓ All 'frameworks' fields are lists")
            print("✓ Known controls have expected frameworks")
            print("✓ CSV file was generated successfully")
            print(f"✓ Total controls: {len(controls)}")
            
            controls_with_frameworks = sum(1 for c in controls if len(c['frameworks']) > 0)
            print(f"✓ Controls with frameworks: {controls_with_frameworks}")
            print(f"✓ Controls without frameworks: {len(controls) - controls_with_frameworks}")
            
            return True
            
    finally:
        # Restore original directory
        os.chdir(original_dir)

if __name__ == '__main__':
    success = test_framework_references()
    sys.exit(0 if success else 1)
