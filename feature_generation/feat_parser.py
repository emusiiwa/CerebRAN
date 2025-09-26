# -*- coding: utf-8 -*-
"""
Cuckoo Ransomware Dataset Builder - Python 2.7 Compatible
"""

import json
import os
import csv
from collections import defaultdict

class CuckooRansomwareDatasetBuilder:
    def __init__(self, output_path=None):
        if output_path is None:
            # Use current directory if not specified
            self.output_path = os.getcwd()
        else:
            self.output_path = output_path
           
        # Set up paths
        home_dir = os.path.expanduser("~")
        self.cuckoo_storage = os.path.join(home_dir, ".cuckoo", "storage", "analyses")
        self.cuckoo_scripts = os.path.join(home_dir, "cuckoo-scripts")
        self.feature_vocab = None
       
    def load_feature_vocabulary(self, vocab_filename="feature_vocabulary.json"):
        """Load the feature vocabulary from JSON file in cuckoo-scripts directory"""
        vocab_file = os.path.join(self.cuckoo_scripts, vocab_filename)
       
        try:
            with open(vocab_file, 'r') as f:
                vocab_data = json.load(f)
           
            # Extract the features list and convert to set for fast lookup
            if isinstance(vocab_data, dict) and 'features' in vocab_data:
                self.feature_vocab = set(vocab_data['features'])
            elif isinstance(vocab_data, list):
                self.feature_vocab = set(vocab_data)
            else:
                self.feature_vocab = set()
               
            print("✓ Loaded {:,} features from: {}".format(len(self.feature_vocab), vocab_file))
            return True
           
        except IOError:
            print("✗ Feature vocabulary not found at: {}".format(vocab_file))
            print("  Please ensure feature_vocabulary.json is in: {}".format(self.cuckoo_scripts))
            return False
        except ValueError:
            print("✗ Error reading JSON from: {}".format(vocab_file))
            return False
   
    def get_sample_label(self, sample_id):
        """
        Determine label based on sample ID:
        - Samples 232-630: goodware (0)  
        - Samples 631-1030: ransomware (1)
        """
        if sample_id <= 630:
            return 0  # goodware
        else:
            return 1  # ransomware
   
    def extract_features_from_report(self, sample_id):
        """Extract features from Cuckoo report.json matching your vocabulary format"""
        report_path = os.path.join(self.cuckoo_storage, str(sample_id), "reports", "report.json")
       
        if not os.path.exists(report_path):
            print("⚠ Report not found for sample {}: {}".format(sample_id, report_path))
            return []
       
        try:
            with open(report_path, 'r') as f:
                report = json.load(f)
           
            present_features = []
           
            # 1. Extract API calls (API:FunctionName format)
            if 'behavior' in report and 'apistats' in report['behavior']:
                for api_name in report['behavior']['apistats']:
                    feature_name = "API:{}".format(api_name)
                    if feature_name in self.feature_vocab:
                        present_features.append(feature_name)
           
            # Extract detailed API calls from processes if available
            if 'behavior' in report and 'processes' in report['behavior']:
                for process in report['behavior']['processes']:
                    if 'calls' in process:
                        for call in process['calls']:
                            if 'api' in call:
                                feature_name = "API:{}".format(call['api'])
                                if feature_name in self.feature_vocab:
                                    present_features.append(feature_name)
           
            # 2. Extract FILETYPE features
            if 'target' in report and 'file' in report['target']:
                file_info = report['target']['file']
                if 'type' in file_info:
                    file_type = file_info['type']
                    feature_name = "FILETYPE:{}".format(file_type)
                    if feature_name in self.feature_vocab:
                        present_features.append(feature_name)
           
            # 3. Extract NETWORK features
            if 'network' in report:
                network_data = report['network']
               
                # Network domains
                if 'domains' in network_data:
                    for domain_info in network_data['domains']:
                        if 'domain' in domain_info:
                            domain = domain_info['domain']
                            feature_name = "NETWORK:DOMAIN:{}".format(domain)
                            if feature_name in self.feature_vocab:
                                present_features.append(feature_name)
               
                # Network hosts/IPs
                if 'hosts' in network_data:
                    for host in network_data['hosts']:
                        feature_name = "NETWORK:HOST:{}".format(host)
                        if feature_name in self.feature_vocab:
                            present_features.append(feature_name)
               
                # TCP/UDP ports
                if 'tcp' in network_data:
                    for tcp_conn in network_data['tcp']:
                        if 'dport' in tcp_conn:
                            port = tcp_conn['dport']
                            feature_name = "NETWORK:TCP_DPORT:{}".format(port)
                            if feature_name in self.feature_vocab:
                                present_features.append(feature_name)
                        if 'sport' in tcp_conn:
                            port = tcp_conn['sport']
                            feature_name = "NETWORK:TCP_SPORT:{}".format(port)
                            if feature_name in self.feature_vocab:
                                present_features.append(feature_name)
               
                if 'udp' in network_data:
                    for udp_conn in network_data['udp']:
                        if 'dport' in udp_conn:
                            port = udp_conn['dport']
                            feature_name = "NETWORK:UDP_DPORT:{}".format(port)
                            if feature_name in self.feature_vocab:
                                present_features.append(feature_name)
                        if 'sport' in udp_conn:
                            port = udp_conn['sport']
                            feature_name = "NETWORK:UDP_SPORT:{}".format(port)
                            if feature_name in self.feature_vocab:
                                present_features.append(feature_name)
           
            # 4. Extract SIGNATURE features (very important for ransomware detection)
            if 'signatures' in report:
                for signature in report['signatures']:
                    if 'name' in signature:
                        sig_name = signature['name']
                        feature_name = "SIGNATURE:{}".format(sig_name)
                        if feature_name in self.feature_vocab:
                            present_features.append(feature_name)
           
            # 5. Extract file operations (for API features we might have missed)
            if 'behavior' in report and 'summary' in report['behavior']:
                summary = report['behavior']['summary']
               
                # Registry operations
                if 'keys' in summary:
                    registry_features = [
                        "API:RegOpenKeyExA", "API:RegOpenKeyExW",
                        "API:RegCreateKeyExA", "API:RegCreateKeyExW",
                        "API:RegSetValueExA", "API:RegSetValueExW",
                        "API:RegQueryValueExA", "API:RegQueryValueExW",
                        "API:RegDeleteKeyA", "API:RegDeleteKeyW",
                        "API:RegDeleteValueA", "API:RegDeleteValueW"
                    ]
                   
                    for reg_feature in registry_features:
                        if reg_feature in self.feature_vocab:
                            present_features.append(reg_feature)
               
                # File operations
                if 'files' in summary:
                    file_features = [
                        "API:CreateFileA", "API:CreateFileW",
                        "API:WriteFile", "API:ReadFile",
                        "API:CopyFileA", "API:CopyFileW",
                        "API:MoveFileA", "API:MoveFileW",
                        "API:DeleteFileA", "API:DeleteFileW",
                        "API:FindFirstFileA", "API:FindFirstFileW",
                        "API:FindNextFileA", "API:FindNextFileW"
                    ]
                   
                    for file_feature in file_features:
                        if file_feature in self.feature_vocab:
                            present_features.append(file_feature)
               
                # Mutex operations
                if 'mutexes' in summary:
                    mutex_features = [
                        "API:CreateMutexA", "API:CreateMutexW",
                        "API:OpenMutexA", "API:OpenMutexW"
                    ]
                   
                    for mutex_feature in mutex_features:
                        if mutex_feature in self.feature_vocab:
                            present_features.append(mutex_feature)
           
            # 6. Extract process operations
            if 'behavior' in report and 'processes' in report['behavior']:
                process_features = [
                    "API:CreateProcessA", "API:CreateProcessW",
                    "API:OpenProcess", "API:TerminateProcess",
                    "API:CreateThread", "API:CreateRemoteThread",
                    "API:VirtualAllocEx", "API:WriteProcessMemory",
                    "API:ReadProcessMemory"
                ]
               
                for proc_feature in process_features:
                    if proc_feature in self.feature_vocab:
                        present_features.append(proc_feature)
           
            # 7. Extract crypto operations (critical for ransomware)
            crypto_features = [
                "API:CryptAcquireContextA", "API:CryptAcquireContextW",
                "API:CryptGenKey", "API:CryptEncrypt", "API:CryptDecrypt",
                "API:CryptHashData", "API:CryptCreateHash", "API:CryptReleaseContext"
            ]
           
            for crypto_feature in crypto_features:
                if crypto_feature in self.feature_vocab:
                    present_features.append(crypto_feature)
           
            # 8. Extract service operations
            service_features = [
                "API:ControlService", "API:CreateServiceA", "API:CreateServiceW",
                "API:OpenServiceA", "API:OpenServiceW",
                "API:StartServiceA", "API:StartServiceW",
                "API:DeleteService"
            ]
           
            for service_feature in service_features:
                if service_feature in self.feature_vocab:
                    present_features.append(service_feature)
           
            # 9. Extract network API operations
            network_api_features = [
                "API:WSAConnect", "API:connect", "API:send", "API:recv",
                "API:InternetOpenA", "API:InternetOpenW",
                "API:HttpSendRequestA", "API:HttpSendRequestW",
                "API:InternetConnectA", "API:InternetConnectW",
                "API:WSAStartup", "API:socket", "API:bind", "API:listen"
            ]
           
            for net_feature in network_api_features:
                if net_feature in self.feature_vocab:
                    present_features.append(net_feature)
           
            # 10. Extract additional Windows API features that might be in vocabulary
            additional_api_features = [
                "API:LoadLibraryA", "API:LoadLibraryW",
                "API:GetProcAddress", "API:VirtualAlloc", "API:VirtualProtect",
                "API:CreateDirectoryA", "API:CreateDirectoryW",
                "API:RemoveDirectoryA", "API:RemoveDirectoryW",
                "API:GetSystemDirectoryA", "API:GetSystemDirectoryW",
                "API:GetWindowsDirectoryA", "API:GetWindowsDirectoryW",
                "API:ShellExecuteA", "API:ShellExecuteW",
                "API:WinExec", "API:CreateProcessInternalW"
            ]
           
            for additional_feature in additional_api_features:
                if additional_feature in self.feature_vocab:
                    present_features.append(additional_feature)
           
            # Remove duplicates and return
            return list(set(present_features))
           
        except ValueError:  # JSON decode error in Python 2.7
            print("✗ Error reading JSON for sample {}".format(sample_id))
            return []
        except Exception as e:
            print("✗ Error processing sample {}: {}".format(sample_id, str(e)))
            return []
   
    def build_dataset(self):
        """Build the complete dataset"""
       
        # Load feature vocabulary first
        if not self.load_feature_vocabulary():
            return False
       
        print("Building dataset for samples 232-1030...")
        print("Cuckoo storage path: {}".format(self.cuckoo_storage))
        print("Feature vocabulary path: {}".format(self.cuckoo_scripts))
       
        # Verify paths exist
        if not os.path.exists(self.cuckoo_storage):
            print("✗ Cuckoo storage path not found: {}".format(self.cuckoo_storage))
            return False
           
        if not os.path.exists(self.cuckoo_scripts):
            print("✗ Cuckoo scripts path not found: {}".format(self.cuckoo_scripts))
            return False
       
        # Sample range: 232-1030 (799 samples total)
        sample_ids = list(range(232, 1031))
       
        print("Processing {} samples...".format(len(sample_ids)))
        print("  Goodware: samples 232-630 ({} samples)".format(630-232+1))
        print("  Ransomware: samples 631-1030 ({} samples)".format(1030-631+1))
       
        # Collect features from all samples
        sample_features = {}
        sample_labels = {}
        missing_samples = []
       
        print("\nExtracting features from all samples...")
        processed = 0
       
        for sample_id in sample_ids:
            processed += 1
            if processed % 50 == 0:
                print("Processed {}/{} samples".format(processed, len(sample_ids)))
               
            try:
                features = self.extract_features_from_report(sample_id)
               
                if not features:  # No features found
                    missing_samples.append(sample_id)
               
                sample_features[sample_id] = set(features)
                sample_labels[sample_id] = self.get_sample_label(sample_id)
               
            except Exception as e:
                print("✗ Error processing sample {}: {}".format(sample_id, str(e)))
                missing_samples.append(sample_id)
       
        if missing_samples:
            print("⚠ {} samples had no features or missing reports:".format(len(missing_samples)))
            print("  Missing: {}{}".format(missing_samples[:10], '...' if len(missing_samples) > 10 else ''))
       
        # Get all unique features actually found in the data
        all_found_features = set()
        for features in sample_features.values():
            all_found_features.update(features)
       
        print("\nFeature summary:")
        print("  Features in vocabulary: {:,}".format(len(self.feature_vocab)))
        print("  Features found in data: {:,}".format(len(all_found_features)))
       
        # Use only features that were actually found
        feature_list = sorted(all_found_features)
       
        # Save feature information
        feature_info = {
            'total_features': len(feature_list),
            'feature_list': feature_list,
            'samples_processed': len(sample_ids),
            'missing_samples': missing_samples
        }
       
        info_file = os.path.join(self.output_path, 'dataset_info.json')
        with open(info_file, 'w') as f:
            json.dump(feature_info, f, indent=2)
       
        features_file = os.path.join(self.output_path, 'feature_list.txt')
        with open(features_file, 'w') as f:
            f.write("Cuckoo Dynamic Analysis Features\n")
            f.write("=" * 50 + "\n")
            f.write("Total features: {:,}\n".format(len(feature_list)))
            f.write("Samples processed: {}\n".format(len(sample_ids)))
            f.write("=" * 50 + "\n\n")
            for i, feat in enumerate(feature_list, 1):
                f.write("{:6d}. {}\n".format(i, feat))
       
        # Build and save CSV
        print("\nBuilding one-hot encoded matrix ({} x {})...".format(len(sample_ids), len(feature_list)))
       
        output_file = os.path.join(self.output_path, 'dataset.csv')
       
        with open(output_file, 'w') as csvfile:
            # Create header
            header = ['sample_id', 'label'] + feature_list
            writer = csv.writer(csvfile)
            writer.writerow(header)
           
            # Write data rows
            processed = 0
            for sample_id in sample_ids:
                processed += 1
                if processed % 100 == 0:
                    print("Built matrix for {}/{} samples".format(processed, len(sample_ids)))
               
                row = [sample_id, sample_labels[sample_id]]
               
                # One-hot encode features
                sample_feat_set = sample_features[sample_id]
                for feat in feature_list:
                    row.append(1 if feat in sample_feat_set else 0)
               
                writer.writerow(row)
       
        # Final statistics
        ransomware_count = sum(sample_labels.values())
        goodware_count = len(sample_labels) - ransomware_count
       
        file_size_mb = os.path.getsize(output_file) / (1024.0 * 1024.0)
       
        print("\n✓ Dataset created successfully!")
        print("  Final shape: {:,} samples x {:,} columns".format(len(sample_ids), len(feature_list) + 2))
        print("  Goodware (0): {:,} samples".format(goodware_count))
        print("  Ransomware (1): {:,} samples".format(ransomware_count))
        print("  File size: {:.1f} MB".format(file_size_mb))
        print("  Output: {}".format(output_file))
       
        return True

# Usage
if __name__ == "__main__":
    print("Cuckoo Ransomware Dataset Builder (Python 2.7)")
    print("=" * 50)
   
    # Initialize builder
    builder = CuckooRansomwareDatasetBuilder()
   
    # Build the dataset
    success = builder.build_dataset()
   
    if success:
        print("\nNext steps:")
        print("1. Review dataset_info.json for processing details")
        print("2. Check feature_list.txt to see all extracted features")
        print("3. Open dataset.csv to verify the structure")
        print("4. Consider feature selection for ML experiments")
        print("\nYour dataset is ready for machine learning!")
    else:
        print("\nDataset creation failed. Please check the error messages above.")

