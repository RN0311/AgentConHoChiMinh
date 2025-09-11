import asyncio
import json
import random
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import time

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    print("🚫 Ollama not available - using mock responses")

class ThreatLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class EventType(Enum):
    SUSPICIOUS_LOGIN = "suspicious_login"
    PORT_SCAN = "port_scan"
    DOS_ATTACK = "dos_attack"
    MALWARE_DETECTED = "malware_detected"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"

@dataclass
class NetworkEvent:
    timestamp: datetime
    source_ip: str
    dest_ip: str
    port: int
    event_type: EventType
    raw_log: str
    threat_level: ThreatLevel = ThreatLevel.LOW
    analyzed: bool = False

@dataclass
class ThreatAnalysis:
    event_id: str
    threat_level: ThreatLevel
    confidence: float
    description: str
    recommendations: List[str]
    indicators: List[str]

@dataclass
class ResponseAction:
    action_type: str
    target: str
    priority: int
    description: str
    automated: bool

class NetworkDataGenerator:
    def __init__(self):
        self.suspicious_ips = ["192.168.1.100", "10.0.0.50", "172.16.1.200"]
        self.normal_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
        self.ports = [22, 80, 443, 3389, 21, 25, 53, 135, 445]
        
    def generate_log_entry(self) -> str:
        ip = random.choice(self.suspicious_ips + self.normal_ips)
        dest = random.choice(self.normal_ips)
        port = random.choice(self.ports)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if ip in self.suspicious_ips:
            events = [
                f"FAILED LOGIN attempt from {ip} to {dest}:22 - invalid credentials",
                f"PORT SCAN detected from {ip} scanning {dest} ports 1-1000",
                f"SUSPICIOUS TRAFFIC {ip} -> {dest}:{port} unusual payload size",
                f"MALWARE SIGNATURE detected in traffic from {ip}",
                f"UNAUTHORIZED ACCESS attempt {ip} -> {dest}:445 SMB"
            ]
        else:
            events = [
                f"NORMAL LOGIN {ip} -> {dest}:22 successful authentication",
                f"HTTP REQUEST {ip} -> {dest}:80 GET /index.html",
                f"DNS QUERY {ip} -> {dest}:53 A record lookup",
                f"HTTPS CONNECTION {ip} -> {dest}:443 TLS handshake"
            ]
        
        event = random.choice(events)
        return f"[{timestamp}] {event}"
    
    def generate_network_events(self, count: int = 3) -> List[NetworkEvent]:
        events = []
        for i in range(count):
            log = self.generate_log_entry()
            
            event_type = EventType.SUSPICIOUS_LOGIN
            if "PORT SCAN" in log:
                event_type = EventType.PORT_SCAN
            elif "MALWARE" in log:
                event_type = EventType.MALWARE_DETECTED
            elif "UNAUTHORIZED" in log:
                event_type = EventType.UNAUTHORIZED_ACCESS
            elif "FAILED LOGIN" in log:
                event_type = EventType.SUSPICIOUS_LOGIN
            
            source_ip = log.split("from ")[1].split(" ")[0] if "from " in log else "192.168.1.1"
            dest_ip = log.split("to ")[1].split(":")[0] if "to " in log else "192.168.1.2"
            port = 22
            
            if ":" in log and "to " in log:
                try:
                    port = int(log.split(":")[-1].split(" ")[0])
                except:
                    port = 22
            
            event = NetworkEvent(
                timestamp=datetime.now() - timedelta(minutes=random.randint(0, 60)),
                source_ip=source_ip,
                dest_ip=dest_ip,
                port=port,
                event_type=event_type,
                raw_log=log
            )
            events.append(event)
        
        return events

class ThreatAnalysisAgent:
    def __init__(self, model_name: str = "deepseek-r1:latest"):
        self.model_name = model_name
        self.use_ollama = OLLAMA_AVAILABLE
        
    async def analyze_event(self, event: NetworkEvent) -> ThreatAnalysis:
        print("🤖 AI Agent analyzing threat...")
        await asyncio.sleep(1.5)  # Give time for audience to see the analysis step
        
        if self.use_ollama:
            try:
                return await self._ollama_analysis(event)
            except Exception:
                return self._fallback_analysis(event)
        else:
            return self._fallback_analysis(event)
    
    async def _ollama_analysis(self, event: NetworkEvent) -> ThreatAnalysis:
        prompt = f"""Analyze this network security event:

Event Type: {event.event_type.value}
Source IP: {event.source_ip}
Destination IP: {event.dest_ip}
Port: {event.port}
Log: {event.raw_log}

Provide analysis in JSON format:
{{
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0.85,
  "description": "Brief threat description",
  "recommendations": ["action1", "action2"],
  "indicators": ["indicator1", "indicator2"]
}}"""

        response = ollama.chat(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1}
        )
        
        try:
            analysis_data = json.loads(response['message']['content'])
            return ThreatAnalysis(
                event_id=f"{event.source_ip}_{int(time.time())}",
                threat_level=ThreatLevel[analysis_data['threat_level']],
                confidence=analysis_data['confidence'],
                description=analysis_data['description'],
                recommendations=analysis_data['recommendations'],
                indicators=analysis_data['indicators']
            )
        except:
            return self._fallback_analysis(event)
    
    def _fallback_analysis(self, event: NetworkEvent) -> ThreatAnalysis:
        threat_mapping = {
            EventType.SUSPICIOUS_LOGIN: (ThreatLevel.MEDIUM, "Potential brute force attack"),
            EventType.PORT_SCAN: (ThreatLevel.HIGH, "Network reconnaissance detected"),
            EventType.MALWARE_DETECTED: (ThreatLevel.CRITICAL, "Malicious software identified"),
            EventType.UNAUTHORIZED_ACCESS: (ThreatLevel.HIGH, "Unauthorized system access"),
            EventType.DOS_ATTACK: (ThreatLevel.CRITICAL, "Denial of service attack"),
            EventType.DATA_EXFILTRATION: (ThreatLevel.CRITICAL, "Data theft attempt")
        }
        
        threat_level, description = threat_mapping.get(event.event_type, (ThreatLevel.LOW, "Unknown event"))
        
        return ThreatAnalysis(
            event_id=f"{event.source_ip}_{int(time.time())}",
            threat_level=threat_level,
            confidence=0.7,
            description=description,
            recommendations=["Monitor source IP", "Review access logs"],
            indicators=[event.source_ip, f"Port {event.port}"]
        )

class ResponseAgent:
    def __init__(self, model_name: str = "deepseek-r1:latest"):
        self.model_name = model_name
        self.use_ollama = OLLAMA_AVAILABLE
        
    async def generate_response(self, analysis: ThreatAnalysis, event: NetworkEvent) -> List[ResponseAction]:
        print("⚡ Response Agent generating actions...")
        await asyncio.sleep(1.2)  # Give time for audience to see the response generation
        
        if self.use_ollama:
            try:
                return await self._ollama_response(analysis, event)
            except Exception:
                return self._fallback_response(analysis, event)
        else:
            return self._fallback_response(analysis, event)
    
    async def _ollama_response(self, analysis: ThreatAnalysis, event: NetworkEvent) -> List[ResponseAction]:
        prompt = f"""Generate incident response actions for this threat:

Threat Level: {analysis.threat_level.name}
Confidence: {analysis.confidence}
Description: {analysis.description}
Source IP: {event.source_ip}
Event Type: {event.event_type.value}

Provide response actions in JSON format:
{{
  "actions": [
    {{
      "action_type": "BLOCK_IP|ISOLATE_HOST|ALERT|INVESTIGATE",
      "target": "{event.source_ip}",
      "priority": 3,
      "description": "Action description",
      "automated": true
    }}
  ]
}}"""

        response = ollama.chat(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1}
        )
        
        try:
            response_data = json.loads(response['message']['content'])
            return [
                ResponseAction(**action) for action in response_data['actions']
            ]
        except:
            return self._fallback_response(analysis, event)
    
    def _fallback_response(self, analysis: ThreatAnalysis, event: NetworkEvent) -> List[ResponseAction]:
        actions = []
        
        if analysis.threat_level == ThreatLevel.CRITICAL:
            actions.append(ResponseAction(
                action_type="BLOCK_IP",
                target=event.source_ip,
                priority=1,
                description=f"Block malicious IP {event.source_ip}",
                automated=True
            ))
            actions.append(ResponseAction(
                action_type="ALERT",
                target="SOC_TEAM",
                priority=1,
                description="Critical threat detected - immediate attention required",
                automated=True
            ))
        
        elif analysis.threat_level == ThreatLevel.HIGH:
            actions.append(ResponseAction(
                action_type="INVESTIGATE",
                target=event.source_ip,
                priority=2,
                description=f"Investigate suspicious activity from {event.source_ip}",
                automated=False
            ))
            actions.append(ResponseAction(
                action_type="ALERT",
                target="SOC_TEAM",
                priority=2,
                description="High-priority security event detected",
                automated=True
            ))
        
        else:
            actions.append(ResponseAction(
                action_type="MONITOR",
                target=event.source_ip,
                priority=3,
                description=f"Monitor {event.source_ip} for additional suspicious activity",
                automated=True
            ))
        
        return actions

class NetworkMonitoringSystem:
    def __init__(self):
        self.data_generator = NetworkDataGenerator()
        self.threat_agent = ThreatAnalysisAgent()
        self.response_agent = ResponseAgent()
        self.processed_events = []
        
    async def process_events(self, events: List[NetworkEvent]):
        print(f"\n🔍 Processing {len(events)} network events...")
        print("=" * 60)
        
        for i, event in enumerate(events, 1):
            print(f"\n📊 Event {i}: {event.event_type.value}")
            print(f"🌐 Source: {event.source_ip} -> Dest: {event.dest_ip}:{event.port}")
            print(f"📝 Log: {event.raw_log}")
            
            await asyncio.sleep(1)  # Pause to let audience read the event
            
            analysis = await self.threat_agent.analyze_event(event)
            
            # Get threat level emoji
            threat_emoji = {
                ThreatLevel.LOW: "🟢",
                ThreatLevel.MEDIUM: "🟡", 
                ThreatLevel.HIGH: "🟠",
                ThreatLevel.CRITICAL: "🔴"
            }.get(analysis.threat_level, "⚪")
            
            print(f"\n🔍 Threat Analysis:")
            print(f"  {threat_emoji} Level: {analysis.threat_level.name}")
            print(f"  📈 Confidence: {analysis.confidence:.2f}")
            print(f"  📋 Description: {analysis.description}")
            
            if analysis.threat_level.value >= ThreatLevel.MEDIUM.value:
                responses = await self.response_agent.generate_response(analysis, event)
                print(f"\n⚡ Response Actions:")
                for action in responses:
                    auto_flag = "🤖 [AUTO]" if action.automated else "👤 [MANUAL]"
                    action_emoji = "🛡️" if action.action_type == "BLOCK_IP" else "🚨" if action.action_type == "ALERT" else "🔍"
                    print(f"  {auto_flag} {action_emoji} {action.action_type}: {action.description}")
            
            self.processed_events.append((event, analysis))
            
            print(f"\n⏳ Processing next event...")
            await asyncio.sleep(2)  # Longer pause between events for demo
        
        await self.generate_summary()
    
    async def generate_summary(self):
        print(f"\n{'='*60}")
        print("📊 MONITORING SUMMARY")
        print("=" * 60)
        
        await asyncio.sleep(1)  # Pause before showing summary
        
        total_events = len(self.processed_events)
        threat_counts = {level: 0 for level in ThreatLevel}
        
        for event, analysis in self.processed_events:
            threat_counts[analysis.threat_level] += 1
        
        print(f"📈 Total Events Processed: {total_events}")
        print(f"📊 Threat Level Distribution:")
        
        level_emojis = {
            ThreatLevel.LOW: "🟢",
            ThreatLevel.MEDIUM: "🟡", 
            ThreatLevel.HIGH: "🟠",
            ThreatLevel.CRITICAL: "🔴"
        }
        
        for level, count in threat_counts.items():
            if count > 0:  # Only show levels that have events
                percentage = (count / total_events) * 100 if total_events > 0 else 0
                emoji = level_emojis.get(level, "⚪")
                print(f"  {emoji} {level.name}: {count} ({percentage:.1f}%)")
        
        critical_events = [e for e, a in self.processed_events if a.threat_level == ThreatLevel.CRITICAL]
        if critical_events:
            print(f"\n🚨 CRITICAL THREATS DETECTED: {len(critical_events)}")
            for event, analysis in [(e, a) for e, a in self.processed_events if a.threat_level == ThreatLevel.CRITICAL]:
                print(f"  🔴 {event.source_ip}: {analysis.description}")

async def main():
    print("🛡️  NETWORK MONITORING MULTI-AGENT SYSTEM")
    print("=" * 60)
    
    await asyncio.sleep(1)
    
    if OLLAMA_AVAILABLE:
        print("🤖 Using Ollama AI agents for analysis")
    else:
        print("⚙️  Using rule-based agents (Ollama not available)")
    
    print("🚀 Initializing system...")
    await asyncio.sleep(1.5)
    
    monitoring_system = NetworkMonitoringSystem()
    
    print("📡 Generating network events...")
    await asyncio.sleep(1)
    
    events = monitoring_system.data_generator.generate_network_events(3)  # Changed to 3 events
    
    await monitoring_system.process_events(events)
    
    print(f"\n✅ Demo completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())