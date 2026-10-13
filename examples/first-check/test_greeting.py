import unittest
from greeting import greet


class GreetingTests(unittest.TestCase):
    def test_greets_the_requested_person(self):
        self.assertEqual(greet("reader"), "Hello, reader!")


if __name__ == "__main__":
    unittest.main()
