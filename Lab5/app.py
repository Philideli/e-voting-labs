from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


class ElectionCommission:
    def __init__(self):
        # Generate RSA key pair for the Central Election Commission (ЦВК)
        self.cvk_private_key = RSA.generate(2048)
        self.cvk_public_key = self.cvk_private_key.publickey()

    def generate_keys(self, count):
        # Generate RSA key pairs for voters and candidates
        keys = [RSA.generate(2048) for _ in range(count)]
        return keys

    def register_voters(self, keys):
        # Register voters with their respective public keys
        return {f"Voter{i}": key.publickey() for i, key in enumerate(keys, start=1)}

    def register_candidates(self, keys):
        # Register candidates with their respective public keys
        return {f"Candidate{i}": key.publickey() for i, key in enumerate(keys, start=1)}

    def conduct_voting(self, voters, candidates, vk1, vk2):
        encrypted_ballots_vk1 = {}
        encrypted_ballots_vk2 = {}

        for voter_id, voter_public_key in voters.items():
            # Each voter chooses a candidate
            candidate_id = input(
                f"Voter {voter_id}, choose a candidate: {list(candidates.keys())} ")

            # Divide the voter ID into arbitrary factors
            factors = [2, 3]  # Example factors

            # Create two ballots using different factors
            for factor in factors:
                ballot = f"{voter_id}:{candidate_id}:{factor}"

                # Encrypt the ballot with the public key of VK-1
                encrypted_ballot_vk1 = vk1.encrypt(ballot.encode())
                # Encrypt the ballot with the public key of VK-2
                encrypted_ballot_vk2 = vk2.encrypt(ballot.encode())

                # Sign the message
                signature_vk1 = self.sign_message(encrypted_ballot_vk1, vk1.private_key)
                signature_vk2 = self.sign_message(encrypted_ballot_vk2, vk2.private_key)

                # Send the encrypted ballots and signatures to VK-1 and VK-2
                encrypted_ballots_vk1[voter_id] = (encrypted_ballot_vk1, signature_vk1)
                encrypted_ballots_vk2[voter_id] = (encrypted_ballot_vk2, signature_vk2)

        return encrypted_ballots_vk1, encrypted_ballots_vk2

    def verify_and_store_ballots(self, encrypted_ballots, vk):
        stored_ballots = {}

        for voter_id, (encrypted_ballot, signature) in encrypted_ballots.items():
            # Verify the signature
            if self.verify_signature(encrypted_ballot, signature, vk.public_key):
                stored_ballots[voter_id] = (voter_id, encrypted_ballot)
                print(f"Received and verified ballot from Voter {voter_id}")

        return stored_ballots

    def decrypt_ballots(self, stored_ballots, private_key):
        decrypted_ballots = {}

        for voter_id, (encrypted_ballot_id, encrypted_ballot) in stored_ballots.items():
            # Decrypt the ballot using the voter's private key
            cipher = PKCS1_OAEP.new(private_key)
            decrypted_ballot = cipher.decrypt(encrypted_ballot).decode()
            decrypted_ballots[voter_id] = decrypted_ballot

        return decrypted_ballots

    def announce_results(self, decrypted_ballots):
        print("\nElection Results:")
        for voter_id, decrypted_ballot in decrypted_ballots.items():
            print(f"Voter {voter_id} voted for {decrypted_ballot.split(':')[1]}")

    def sign_message(self, message, private_key):
        # Sign the message using PKCS1_v1_5
        h = SHA256.new(message)
        signature = pkcs1_15.new(private_key).sign(h)
        return signature

    def verify_signature(self, message, signature, public_key):
        # Verify the signature using PKCS1_v1_5
        h = SHA256.new(message)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False


class VotingCommission:
    def __init__(self):
        # Generate RSA key pair for the Voting Commission (ВК-1 and ВК-2)
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def encrypt(self, message):
        cipher = PKCS1_OAEP.new(self.public_key)
        ciphertext = cipher.encrypt(message)
        return ciphertext


def main():
    # Start the election
    cvk = ElectionCommission()

    # Generate keys for voters and candidates
    voter_keys = cvk.generate_keys(4)
    candidate_keys = cvk.generate_keys(2)

    # Register voters and candidates
    voters = cvk.register_voters(voter_keys)
    candidates = cvk.register_candidates(candidate_keys)

    # Create two instances of Voting Commission (ВК-1 and ВК-2)
    vk1 = VotingCommission()
    vk2 = VotingCommission()

    # Conduct voting
    encrypted_ballots_vk1, encrypted_ballots_vk2 = cvk.conduct_voting(voters,
                                                                      candidates, vk1,
                                                                      vk2)

    # Verify and store ballots by VK-1 and VK-2
    stored_ballots_vk1 = cvk.verify_and_store_ballots(encrypted_ballots_vk1, vk1)
    stored_ballots_vk2 = cvk.verify_and_store_ballots(encrypted_ballots_vk2, vk2)

    # CVK decrypts ballots
    decrypted_ballots_vk1 = cvk.decrypt_ballots(stored_ballots_vk1, vk1.private_key)
    decrypted_ballots_vk2 = cvk.decrypt_ballots(stored_ballots_vk2, vk2.private_key)

    # Announce results
    cvk.announce_results(decrypted_ballots_vk1)
    cvk.announce_results(decrypted_ballots_vk2)


main()
