from c2.c2_actions import C2Action, ActionRequirementsNotSatisfied
from typing import List


class C2Operation:
    def __init__(self, actions: List[C2Action] = None, name: str = "", description: str = ""):
        if actions is None:
            actions = []
        self.actions = actions
        self.name = name
        self.description = description
        self.num_completed = 0
        self.reported_actions = []
        self.generic = True

    def performOperation(self, connUuid: str):
        for action in self.actions:
            try:
                if isinstance(action, C2Action):
                    cmd_indexes_list = action.performAction(connUuid)
                    cmd_indexes_list = ", ".join([str(i) for i in cmd_indexes_list])
                elif isinstance(action, C2Operation):
                    op = action
                    op.performOperation(connUuid)
                    cmd_indexes_list = ", ".join([
                        reported_action[1] for reported_action in op.reported_actions
                    ])
                else:
                    raise ValueError("Actions of which an Operation is composed must either be of "
                                     "type C2Action or of type C2Operation")
                if action.isSuccessful():
                    self.reported_actions.append((action.name, cmd_indexes_list))
                    self.num_completed += 1
                else:
                    break
            except ActionRequirementsNotSatisfied:
                break
        report = self.reportOperationState()
        return report

    def reportOperationState(self):
        report = f"{self.name} operation: completed {self.num_completed}/{len(self.actions)} actions"
        for reported_action in self.reported_actions:
            report += f"\n'{reported_action[0]}' command indexes: {reported_action[1]}"
        return report

    def describeOperation(self):
        message = f"{self.name}: {self.description}\n"
        if self.generic:
            # actions can't be listed in the case of a specific operation, because they are filled
            # at run-time, as opposed to the case of a generic operation
            message += f"Actions: {', '.join([action.name for action in self.actions])}"
        return message

    def isSuccessful(self) -> bool:
        return self.num_completed == len(self.actions)
