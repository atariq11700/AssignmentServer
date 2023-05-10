from typing import Callable, Any


class MenuOption:
    def __init__(self, name: str, callback: Callable, *callback_args, **callback_kwargs) -> None:
        self.__name = name
        self.__callback = callback
        self.__cb_args = callback_args
        self.__cb_kwargs = callback_kwargs

    def __repr__(self) -> str:
        return self.__name
    

    def __call__(self, *_args: Any, **_kwds: Any) -> Any:
        return self.__callback(*self.__cb_args, **self.__cb_kwargs)

class Menu:
    def __init__(self, name: str) -> None:
        self.__name = name
        self.__options = []

    def __repr__(self) -> str:
        return self.__name


    def add_option(self, option: MenuOption) -> None:
        self.__options.append(option)


    def show(self):
        done = False
        while not done:
            print("--------------------")
            print(self.__name)
            print("--------------------")
            for i, option in enumerate(self.__options):
                print(f"[{i+1}] {option}")
            print(f"[{len(self.__options) + 1}] Back")

            choice = None
            try:
                choice = int(input(":>")) - 1

                if choice < 0 or choice >= (len(self.__options) + 1):
                    raise Exception
            except Exception as e:
                print("Please enter a valid option")

            if choice == len(self.__options):
                done = True
                break
            else:
                self.__options[choice]()