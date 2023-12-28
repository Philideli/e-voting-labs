from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class Voter:
    def __init__(self, name, has_voted=False):
        self.name = name
        self.has_voted = has_voted

    def vote(self):
        if not self.has_voted:
            print(f"{self.name}, виберіть кандидата:")
            vote = int(input())
            self.has_voted = True
            return vote
        else:
            print(f"{self.name}, вже голосував")


class Candidate:
    def __init__(self, name):
        self.name = name
        self.votes = 0


class ElectionAuthority:
    def __init__(self, voters=[], candidates=[]):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        self.votes = []
        self.candidates = candidates
        self.voters = voters

    def __encrypt_vote(self, vote, public_key):
        cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
        return cipher.encrypt(str(vote).encode())

    def __decrypt_vote(self, encrypted_vote):
        cipher = PKCS1_OAEP.new(RSA.import_key(self.private_key))
        decrypted_vote = cipher.decrypt(encrypted_vote)
        return int(decrypted_vote.decode())

    def __blind_sign(self, message):
        h = SHA256.new(message)
        return pkcs1_15.new(RSA.import_key(self.private_key)).sign(h)

    def __is_valid_signature(self, blinded_message, blinded_signature):
        h = SHA256.new(blinded_message)  # Hash the blinded message
        try:
            pkcs1_15.new(RSA.import_key(self.public_key)).verify(h, blinded_signature)
            return True
        except (ValueError, TypeError, pkcs1_15.pkcs1_15Error):
            return False

    def calculate_results(self):
        # Етап підведення підсумків
        for vote in self.votes:
            message = vote[0]
            signature = vote[1]
            if self.__is_valid_signature(message, signature):
                decrypted_message = self.__decrypt_vote(message)
                self.candidates[decrypted_message - 1].votes += 1

    def print_results(self):
        print("Результати голосування:")
        for candidate in self.candidates:
            print(f"{candidate.name}: {candidate.votes} голосів")

    def election(self):
        # Етап голосування
        for voter in self.voters:
            vote = voter.vote()
            if vote is not None:
                if 1 <= vote <= len(self.candidates):
                    encrypted_vote = self.__encrypt_vote(vote, self.public_key)
                    blind_signature = self.__blind_sign(encrypted_vote)
                    self.votes.append((encrypted_vote, blind_signature))
                    print("Голос зараховано.")
                else:
                    print("Неправильний варіант, спорчений бюлетень.")


def main():
    # Етап реєстрації виборців та кандидатів
    voters = [Voter("Voter1"), Voter("Voter2"), Voter("Voter3"), Voter("Voter4")]
    candidates = [Candidate("Candidate1"), Candidate("Candidate2")]

    authority = ElectionAuthority(voters=voters, candidates=candidates)
    authority.election()
    authority.calculate_results()
    authority.print_results()


if __name__ == "__main__":
    main()
