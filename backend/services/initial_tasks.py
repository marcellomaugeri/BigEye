"""The ordered initial backbone task records."""


class InitialTaskService:
    def names(self) -> list[str]:
        return ["repository clone", "LLVM toolchain preparation", "repository analysis"]
