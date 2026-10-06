from internal.models import Event

class Generator:
    def __init__(self):
        self.events: list[Event] = []

    def add_event(self, event: Event):
        self.events.append(event)

    def generate(self, analysis_id: str) -> str:
        report = []
        report.append("SANDBOX ANALYSIS REPORT")
        report.append("=======================\n")
        report.append(f"Analysis ID: {analysis_id}\n")
        
        report.append("RAW EVENTS (Milestones 1 & 2)")
        report.append("-----------------------------")
        
        if not self.events:
            report.append("No events captured.")
        else:
            for event in self.events:
                report.append(str(event))
                
        return "\n".join(report)
