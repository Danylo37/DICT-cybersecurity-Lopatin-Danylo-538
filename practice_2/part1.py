class PasswordChecker:
    def __init__(self):
        self.U = 0
        self.pw = ""
        self.has_lower = False
        self.has_upper = False
        self.N = 0
        self.S = 0

    def check_password(self, pw: str):
        if not pw:
            print("Паролю немає")
            return

        self.U = 0
        self.pw = pw

        self._check_length()
        self._check_letters()
        self._check_digits()
        self._check_specials()
        self._check_complexity()

        strength = self._get_strength()
        print(f"Пароль {strength}, {self.U}")

    def _check_length(self):
        L = len(self.pw)
        if L <= 4:
            self.U = 0
        elif L <= 7:
            self.U = 6
        elif L <= 15:
            self.U = 12
        else:
            self.U = 18

    def _check_letters(self):
        self.has_lower = any(c.islower() for c in self.pw)
        self.has_upper = any(c.isupper() for c in self.pw)
        if self.has_lower and self.has_upper:
            self.U += 7
        elif self.has_lower or self.has_upper:
            self.U += 5

    def _check_digits(self):
        self.N = sum(c.isdigit() for c in self.pw)
        if self.N == 0:
            return
        elif self.N <= 2:
            self.U += 5
        else:
            self.U += 7

    def _check_specials(self):
        special_characters = "#$%@"
        self.S = sum(c in special_characters for c in self.pw)
        if self.S == 1:
            self.U += 5
        elif self.S >= 2:
            self.U += 10

    def _check_complexity(self):
        passed_checks = sum([self.has_lower, self.has_upper, self.N > 0, self.S > 0])

        if passed_checks == 4:
            self.U += 6
        elif passed_checks == 3:
            self.U += 4

    def _get_strength(self):
        if self.U < 16:
            return "дуже слабкий"
        elif self.U < 25:
            return "слабкий"
        elif self.U < 35:
            return "середній"
        elif self.U < 45:
            return "сильний"
        else:
            return "дуже сильний"


if __name__ == '__main__':
    passwords = ["", "a12", "abc123", "abc123@", "Abcd123@", "ABCdefGHIjk#123@"]

    checker = PasswordChecker()

    for password in passwords:
        print(f"Пароль: \"{password}\"")
        checker.check_password(password)
        print()
