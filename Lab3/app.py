import random
import secrets
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import DSS

class Voter:
    def __init__(self, name, registry):
        self.id = name
        self.election_vote = None
        self.registration_number = registry.generate_registration_number(self.id)

    def vote(self, authority):
        print(f"{self.id}, виберіть кандидата (введіть номер):")
        self.election_vote = int(input())
        encrypted_ballot, signature = authority.receive_vote(self.id, self.registration_number, self.election_vote)
        print(encrypted_ballot, signature)
        if encrypted_ballot and signature:
            print("Ваш голос успішно зашифровано та підписано.")
        else:
            print("Помилка при обробці голосу.")

class Candidate:
    def __init__(self, name):
        self.name = name
        self.votes = 0

class BallotRegistry:
    def __init__(self):
        self.registration_numbers = {}

    def generate_registration_number(self, voter_id):
        registration_number = random.randint(1000, 9999)
        self.registration_numbers[registration_number] = voter_id
        return registration_number

class ElectionAuthority:
    def __init__(self, ballot_registry, candidates):
        self.ballot_registry = ballot_registry
        self.registered_voters = set()
        self.votes = {}
        self.candidates = candidates

    def receive_vote(self, voter_id, registration_number, election_vote):
        if registration_number in self.ballot_registry.registration_numbers and \
                registration_number not in self.registered_voters:
            encrypted_ballot, signature = self.encrypt_vote(election_vote)
            if encrypted_ballot and signature:
                self.registered_voters.add(registration_number)
                self.votes[voter_id] = (registration_number, encrypted_ballot, signature)
                return encrypted_ballot, signature
        return None, None

    def generate_random_bytes(self, N):
        random_bytes = Random.new().read(N)
        return random_bytes

    def encrypt_vote(self, election_vote):
        # Simplified encryption for demonstration purposes
        print(election_vote)
        elgamal_key = ElGamal.generate(2048, self.generate_random_bytes)
        print(elgamal_key)
        cipher = PKCS1_OAEP.new(elgamal_key.publickey())
        encrypted_ballot = cipher.encrypt(str(election_vote).encode())
        # Sign the encrypted vote
        h = SHA256.new(encrypted_ballot)
        signer = DSS.new(elgamal_key, 'fips-186-3')
        signature = signer.sign(h)
        return encrypted_ballot, signature

    def publish_results(self):
        print("Election Results:")
        for voter_id, (registration_number, encrypted_ballot, _) in self.votes.items():
            candidate_index = self.decrypt_ballot(encrypted_ballot)
            candidate = self.candidates[candidate_index]
            print(f"Voter {voter_id}: Registration Number - {registration_number}, Voted for - {candidate.name}")

    def decrypt_ballot(self, encrypted_ballot):
        # Simplified decryption for demonstration purposes
        elgamal_key = ElGamal.generate(2048, self.generate_random_bytes)
        cipher = PKCS1_OAEP.new(elgamal_key)
        decrypted_ballot = int(cipher.decrypt(encrypted_ballot).decode())
        return decrypted_ballot

def main():
    candidates = [Candidate("Candidate 1"), Candidate("Candidate 2")]
    ballot_registry = BallotRegistry()
    authority = ElectionAuthority(ballot_registry, candidates)
    voters = [Voter(f"Voter{i}", ballot_registry) for i in range(1, 5)]

    for voter in voters:
        voter.vote(authority)

    authority.publish_results()

if __name__ == "__main__":
    main()
