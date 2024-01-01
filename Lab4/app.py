import random

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA, ElGamal
from Crypto.Signature import DSS


class Voter:
    def __init__(self, name, can_vote=True):
        self.name = name
        self.can_vote = can_vote
        self.rsa_public_key, self.rsa_private_key = self.generate_rsa_key_pair()
        self.elgamal_public_key, self.elgamal_private_key = self.generate_elgamal_key_pair()

    def generate_rsa_key_pair(self):
        key = RSA.generate(2048)
        return key.publickey(), key

    def generate_elgamal_key_pair(self):
        key = ElGamal.generate(2048, Random.new().read)
        return key.publickey(), key

    def encrypt_message(self, message, recipient_public_key):
        cipher = PKCS1_OAEP.new(recipient_public_key)
        return cipher.encrypt(message.encode())

    def decrypt_message(self, ciphertext, key):
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(ciphertext).decode()

    def sign_message(self, message):
        h = SHA256.new(message.encode())
        signer = DSS.new(self.elgamal_private_key, 'fips-186-3')
        signature = signer.sign(h)
        return signature

    def verify_signature(self, message, signature, signer_public_key):
        h = SHA256.new(message.encode())
        verifier = DSS.new(signer_public_key, 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


class ElectionAuthority:
    def __init__(self, candidates):
        self.candidates = candidates
        self.voters = []
        self.ballots = []

    def add_voter(self, voter):
        self.voters.append(voter)

    def conduct_election(self):
        # Voting Phase
        for voter in self.voters:
            if voter.can_vote:
                chosen_candidate = random.choice(self.candidates)
                encrypted_ballot = voter.encrypt_message(chosen_candidate,
                                                         self.voters[0].rsa_public_key)
                self.ballots.append((encrypted_ballot, voter.elgamal_private_key))

        for voter in self.voters:
            print(f"Voter {voter.id} is doing shuffling...")
            # Shuffling Phase
            shuffled_ballots = random.sample(self.ballots, len(self.ballots))
            for i in range(len(self.ballots)):
                self.ballots[i] = shuffled_ballots[i]

            # Verification and Signing Phase
            for i, (encrypted_ballot, private_key) in enumerate(self.ballots):
                decrypted_ballot = self.voters[i].decrypt_message(encrypted_ballot,
                                                                  private_key)
                if self.voters[i].can_vote and decrypted_ballot not in self.candidates:
                    print(
                        f"Error: {self.voters[i].name} did not cast a valid vote or voted for an invalid candidate.")

                # Verification of Signature
                if i > 0 and not self.voters[i - 1].verify_signature(str(encrypted_ballot),
                                                                     self.voters[
                                                                         i].sign_message(
                                                                         str(encrypted_ballot)),
                                                                     self.voters[
                                                                         i - 1].elgamal_public_key):
                    print(f"Error: Signature of {self.voters[i].name} is not valid.")

        # Counting Votes
        decrypted_ballots = [
            self.voters[i].decrypt_message(encrypted_ballot, private_key) for
            (encrypted_ballot, private_key) in self.ballots]
        vote_counts = {candidate: decrypted_ballots.count(candidate) for candidate in
                       self.candidates}
        print("Election Results:")
        for candidate, count in vote_counts.items():
            print(f"{candidate}: {count} votes")


def main():
    candidates = ["Candidate 1", "Candidate 2"]
    authority = ElectionAuthority(candidates)
    voters = [Voter(f"Voter {i}") for i in range(1, 5)]

    for voter in voters:
        authority.add_voter(voter)

    authority.conduct_election()


if __name__ == "__main__":
    main()
