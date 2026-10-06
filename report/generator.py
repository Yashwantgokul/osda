from internal.models import Event
import os
import sys

class Generator:
    def __init__(self):
        self.events: list[Event] = []

    def add_event(self, event: Event):
        self.events.append(event)

    def generate(self, analysis_id: str, tree=None, evaluation=None, target=None, duration=None, color=None) -> str:
        report = []
        report.append("SANDBOX ANALYSIS REPORT")
        report.append("=======================\n")
        report.append(f"Analysis ID: {analysis_id}\n")
        if target:
            report.append(f"Target File: {target}")
        if duration is not None:
            report.append(f"Execution Time: {duration:.2f}s")
        if tree is not None:
            report.extend(["\nPROCESS TREE", "------------", tree.render(evaluation.findings if evaluation else ())])
        if evaluation is not None:
            use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ if color is None else color
            verdict = evaluation.verdict
            if use_color:
                code = {"SAFE": 32, "SUSPICIOUS": 33, "MALICIOUS": 31}[verdict]
                verdict = f"\033[{code}m{verdict}\033[0m"
            report.extend(["\nSECURITY EVALUATION", "-------------------",
                           f"Risk Score: {evaluation.score} / 100", f"Verdict: {verdict}", "\nDetected Findings:"])
            report.extend(f"  [!] {f.severity} (+{f.points}): {f.description}" for f in evaluation.findings)
            if not evaluation.findings:
                report.append("  No heuristic rules matched.")
            recommendation = {"SAFE": "No flagged behavior observed. Review coverage limitations before trusting the file.",
                              "SUSPICIOUS": "Review the findings before running this file on your host.",
                              "MALICIOUS": "Avoid running this file on your host; investigate the flagged behavior."}
            report.extend(["\nRecommendation:", recommendation[evaluation.verdict], "\nCoverage limitations:"])
            report.extend(f"  - {item}" for item in evaluation.limitations)
        
        report.append("RAW EVENTS (Milestones 1 & 2)")
        report.append("-----------------------------")
        
        if not self.events:
            report.append("No events captured.")
        else:
            for event in self.events:
                if tree is not None and event.pid is not None and event.pid not in tree.sandbox_pids():
                    continue
                report.append(str(event))
                
        return "\n".join(report)
