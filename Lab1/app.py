import random

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message):
    message = message.encode()
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, message, signature):
    message = message.encode()
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def xor_cipher(message, key):
    return ''.join(chr(ord(c) ^ key) for c in message)


candidates = ["C1", "C2", "C3"]
voters = {"Voter1": {}, "Voter2": {}, "Voter3": {}, "Voter4": {}}

cec_private_key, cec_public_key = generate_rsa_keys()
for voter in voters:
    private_key, public_key = generate_rsa_keys()
    voters[voter]['private_key'] = private_key
    voters[voter]['public_key'] = public_key


# Voting process
def vote(voter_id, candidate):
    if voter_id not in voters:
        return "Invalid voter"
    if candidate not in candidates:
        return "Invalid candidate"

    voter_private_key = voters[voter_id]['private_key']
    vote = f"Vote for {candidate}"
    signature = sign_message(voter_private_key, vote)

    encrypted_vote = xor_cipher(vote, 5)  # Using a simple XOR for demonstration

    return (encrypted_vote, signature)


voting_results = []
for voter in voters:
    candidate = random.choice(candidates)
    result = vote(voter, candidate)
    voting_results.append((voter, result))


def decrypt_and_verify_votes(voting_results):
    vote_count = {candidate: 0 for candidate in candidates}
    processed_voters = set()

    for voter, (encrypted_vote, signature) in voting_results:
        if voter in processed_voters:
            print(f"{voter} has already voted. Duplicate vote detected!")
            continue

        decrypted_vote = xor_cipher(encrypted_vote,
                                    5)  # Decrypting using the same XOR method

        candidate_name = decrypted_vote.split(" ")[-1]
        if candidate_name not in candidates:
            print(f"Invalid vote from {voter}.")
            continue

        if verify_signature(voters[voter]['public_key'], decrypted_vote, signature):
            vote_count[candidate_name] += 1
            processed_voters.add(voter)
            print(voter, candidate_name)
        else:
            print(f"Invalid signature from {voter}.")

    return vote_count


if __name__ == "__main__":
    final_vote_count = decrypt_and_verify_votes(voting_results)
