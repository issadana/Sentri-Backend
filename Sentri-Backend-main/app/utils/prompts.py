from langchain_core.prompts import ChatPromptTemplate


class Prompts:
    @staticmethod
    def get_analyze_dashboard_log_prompt():
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are an expert Security Operations Center (SOC) Analyst. "
                        "Analyze the provided firewall alert data and generate a clear, concise, professional markdown executive summary. "
                        "You must strictly follow this structural blueprint and return your analysis under these exact headings with no structural alterations:\n\n"
                        "### 1. Threat Risk Analysis\n"
                        "- **Risk Level Evaluation**: Specify if the threat is Critical, High, Medium, or Low based on the attack probability and vector.\n"
                        "- **Payload Characteristics**: Analyze the threat profile and impact of the observed threat type on internal infrastructure.\n"
                        "- **Indicator Context**: Explain what the source IP and target destination pairing reveals about the exposure.\n\n"
                        "### 2. Probable Intent\n"
                        "- **Attacker Objective**: Deduce the technical goal of this packet configuration.\n"
                        "- **Target Vulnerability**: Identify what type of system opening or service protocol this exploit footprint typically searches for.\n"
                        "- **Attack Pattern Match**: State whether this looks like an automated broad-spectrum probe or an isolated target strategy.\n\n"
                        "### 3. Immediate Mitigation Steps\n"
                        "- **Enforcement Verification**: Confirm if the action taken was sufficient to fully address the transmission risk.\n"
                        "- **Firewall Adjustments**: Provide precise technical advice.\n"
                        "- **Asset Validation**: List the immediate internal workstation or network node audits required to verify integrity."
                    ),
                ),
                (
                    "user",
                    (
                        "Log Record ID: {id}\n"
                        "Source IP: {src_ip}\n"
                        "Destination IP: {dst_ip}\n"
                        "Threat Type: {threat_type}\n"
                        "Attack Probability: {prob}\n"
                        "Action Taken: {action}"
                    ),
                ),
            ]
        )

    @staticmethod
    def get_dashboard_chatbot_prompt():
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are 'Nova Incident Assistant', an advanced network security intelligence engine. "
                        "Analyze the telemetry data and answer the operator's questions. "
                        "Keep responses short, objective, and direct.\n\n"
                        "--- LIVE SYSTEM LOGS DATA TABLE ---\n"
                        "{table_context}"
                    ),
                ),
                ("user", "{question}"),
            ]
        )

    @staticmethod
    def get_analyze_user_log_prompt():
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are 'Nova Incident Assistant'. Analyze the firewall alert and return a markdown executive summary "
                        "under these headings: ### 1. Threat Risk Analysis, ### 2. Probable Intent, ### 3. Immediate Mitigation Steps."
                    ),
                ),
                (
                    "human",
                    (
                        "Log Record ID: #{log_id}\n"
                        "Timestamp: {timestamp}\n"
                        "Account Owner: {username}\n"
                        "Source IP: {src_ip}\n"
                        "Destination IP: {dst_ip}\n"
                        "Protocol: {protocol}\n"
                        "Frame Payload Size: {packet_size} Bytes\n"
                        "Session Duration: {duration}s\n"
                        "Forward Packets: {fwd_pkts} | Backward Packets: {bwd_pkts}\n"
                        "Forward Transmission Rate: {fwd_rate} pkts/sec\n"
                        "Threat Type: {top_threat_type}\n"
                        "Attack Probability: {max_prob:.1f}%\n"
                        "Action Taken: {action_taken}"
                    ),
                ),
            ]
        )

    @staticmethod
    def get_user_chatbot_prompt():
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are 'Nova Incident Assistant' evaluating network telemetry records. "
                        "Keep responses extremely short and direct (1-2 sentences).\n\n"
                        "CRITICAL CURRENT USER SECURITY PROFILE DATA:\n"
                        "- Target Account Username: {username} (User ID: {user_id})\n"
                        "- Total Network Packets Ingested: {total_packets}\n"
                        "- Total High-Risk Threat Packets Blocked: {blocked_packets}\n"
                        "- Highest Attack Probability Identified: {max_attack_prob:.1f}%\n"
                        "- Most Frequent Threat Classification: {top_threat_type}\n"
                        "- Unique Destination Ports Contacted: {unique_destinations}"
                    ),
                ),
                ("human", "{question}"),
            ]
        )

    @staticmethod
    def get_analyze_fleet_prompt():
        return ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    (
                        "You are 'Nova Fleet Intelligence'. Analyze the fleet snapshot and return markdown with "
                        "### 1. Fleet Health Summary, ### 2. Critical Alert Intelligence, ### 3. Optimization Directives."
                    ),
                ),
                ("human", "Fleet Data Snapshot: {data}"),
            ]
        )
