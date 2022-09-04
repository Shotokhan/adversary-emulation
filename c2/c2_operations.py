from c2.c2_actions import C2Action, ActionRequirementsNotSatisfied
from typing import List


class C2Operation:
    def __init__(self, actions: List[C2Action], name: str = "", description: str = ""):
        self.actions = actions
        self.name = name
        self.description = description
        self.num_completed = 0

    def performOperation(self, connUuid: str):
        for action in self.actions:
            try:
                action.performAction(connUuid)
                self.num_completed += 1
            except ActionRequirementsNotSatisfied:
                break
        report = self.reportOperationState()
        return report

    def reportOperationState(self):
        report = f"{self.name} operation: completed {self.num_completed}/{len(self.actions)} actions"
        return report

    def describeOperation(self):
        message = f"{self.name}: {self.description}\n"
        message += f"Actions: {', '.join([action.name for action in self.actions])}"
        return message
