# Task
Network Vulnerability Assessment and Hardening Project
This project focuses on the full lifecycle of network security operations within a simulated environment. The goal is to transition from a conceptual security objective to a functional,
secure technical environment by identifying vulnerabilities and implementing robust defensive hardening measures.
=> Objectives:
- Reconnaissance: Conduct initial discovery and asset mapping.
- Vulnerability Identification: Use deep inspection to find known CVEs and misconfigurations.
- Defensive Hardening: Apply system and network-level security controls to mitigate risks.
  Requirements:
  => Functional Requirements:
  - Network Discovery: Identify live assets, hostnames, and IP configurations.
  - Scanning Capabilities: Map protocols and services against CVE databases.
  - Mitigation Framework: Technical capacity to apply security controls.
  - Security Validation: Mechanism for ethical exploitation testing.
    => Non-Functional Requirements:
    - Isolation: Project is confined to a virtual lab to prevent external interference.
    - Reversibility: Use of snapshots for system recovery.
    - Documentation: Comprehensive logging of security states (Before/After).
     => Project Workflow (4-Week Timeline):
      Week	              Phase	                       Core Tasks & Deliverables
      
      Week 1              Reconnaissance              Passive/Active discovery, scanning scripts, and Network Map.
      Week 2              Vulnerability Analysis      Logical configuration of Nessus/OpenVAS and Scan Reports.
      Week 3              Hardening & Mitigation      Disabling non-essential services and applying OS benchmarks.
      Week 4              Validation & Reporting      Execution of Penetration Tests and Final Technical Report.

      => Security Controls Implemented:
          As part of the Week 3 hardening phase, the following measures are applied:
        - Disabling non-essential services.
        - Configuring host-based firewalls.
        - Applying OS-level security benchmarks.

          => Constraints & Risk Management:
                - Resource Allocation: Requires sufficient hardware to support multiple VM instances.
                - Scope: Hardening is prioritized for critical vulnerabilities identified in Week 2.
                - Safety: All intrusive tests are restricted to documented targets within the isolated lab.
                
