"""The ordered initial backbone task records."""


class InitialTaskService:
    def __init__(self, repository_analysis: bool = True):
        self._repository_analysis = repository_analysis

    def names(self) -> list[str]:
        final = "repository analysis" if self._repository_analysis else "repository layer"
        return ["repository clone", "LLVM toolchain preparation", final]
