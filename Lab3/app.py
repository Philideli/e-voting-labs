import random

from Crypto.Hash import SHA256
from Crypto.PublicKey import ElGamal
from Crypto.Signature import DSS


class Voter:
    def __init__(self, name):
        self.name = name
        self.election_vote = None

    def vote(self):
        print(f"{self.name}, виберіть кандидата:")
        self.election_vote = int(input())
        return self.election_vote


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

    def receive_registration_request(self, voter_id):
        return self.ballot_registry.provide_registration_number(voter_id)

    def receive_vote(self, voter_id, registration_number, encrypted_ballot, signature):
        if registration_number in self.ballot_registry.registration_numbers and \
            registration_number not in self.registered_voters:
            if self.verify_signature(encrypted_ballot, signature,
                                     self.ballot_registry.registration_numbers[
                                         registration_number]):
                self.registered_voters.add(registration_number)
                self.votes[voter_id] = (registration_number, encrypted_ballot)
                return True
        return False

    def verify_signature(self, encrypted_ballot, signature, voter_id):
        h = SHA256.new(encrypted_ballot)
        verifier = DSS.new(voter_id.elgamal_key.publickey(), 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    def publish_results(self):
        print("Election Results:")
        for voter_id, (registration_number, encrypted_ballot) in self.votes.items():
            candidate_index = self.decrypt_ballot(encrypted_ballot)
            candidate = self.candidates[candidate_index]
            print(
                f"Voter {voter_id}: Registration Number - {registration_number}, Voted for - {candidate}")

    def decrypt_ballot(self, encrypted_ballot):
        # Simplified decryption for demonstration purposes
        return int(encrypted_ballot.decode())


def main():
    # Create BallotRegistry and VotingCommission with two candidates
    ballot_registry = BallotRegistry()
    candidates = ["Candidate A", "Candidate B"]
    commission1 = VotingCommission(ballot_registry, candidates)
    commission2 = VotingCommission(ballot_registry, candidates)

    # Voter registration process
    voter_id1 = "Alice"
    registration_number1 = commission1.receive_registration_request(voter_id1)

    voter_id2 = "Bob"
    registration_number2 = commission2.receive_registration_request(voter_id2)

    voter_id3 = "Charlie"
    registration_number3 = commission1.receive_registration_request(voter_id3)

    voter_id4 = "David"
    registration_number4 = commission2.receive_registration_request(voter_id4)

    # Voting process
    elgamal_key1 = ElGamal.generate(2048)
    elgamal_key2 = ElGamal.generate(2048)

    # Encrypt the ballots with ElGamal
    encrypted_ballot1 = elgamal_key1.publickey().encrypt(
        str(random.randint(0, len(candidates) - 1)).encode(),
        random.randint(1, elgamal_key1.p - 2))
    encrypted_ballot2 = elgamal_key2.publickey().encrypt(
        str(random.randint(0, len(candidates) - 1)).encode(),
        random.randint(1, elgamal_key2.p - 2))
    encrypted_ballot3 = elgamal_key1.publickey().encrypt(
        str(random.randint(0, len(candidates) - 1)).encode(),
        random.randint(1, elgamal_key1.p - 2))
    encrypted_ballot4 = elgamal_key2.publickey().encrypt(
        str(random.randint(0, len(candidates) - 1)).encode(),
        random.randint(1, elgamal_key2.p - 2))

    # Sign the encrypted ballots with DSA
    signature1 = DSS.new(elgamal_key1, 'fips-186-3').sign(SHA256.new(encrypted_ballot1))
    signature2 = DSS.new(elgamal_key2, 'fips-186-3').sign(SHA256.new(encrypted_ballot2))
    signature3 = DSS.new(elgamal_key1, 'fips-186-3').sign(SHA256.new(encrypted_ballot3))
    signature4 = DSS.new(elgamal_key2, 'fips-186-3').sign(SHA256.new(encrypted_ballot4))

    # Submit votes
    commission1.receive_vote(voter_id1, registration_number1, encrypted_ballot1,
                             signature1)
    commission2.receive_vote(voter_id2, registration_number2, encrypted_ballot2,
                             signature2)
    commission1.receive_vote(voter_id3, registration_number3, encrypted_ballot3,
                             signature3)
    commission2.receive_vote(voter_id4, registration_number4, encrypted_ballot4,
                             signature4)

    # Publishing results
    commission1.publish_results()
    commission2.publish_results()


if __name__ == "__main__":
    main()
