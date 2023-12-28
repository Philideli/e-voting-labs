import hashlib
import random
import math


def generate_rsa_keypair():
    # Generate RSA key pair
    p = 61  # Example prime number, choose larger primes in real-world scenarios
    q = 53  # Example prime number, choose larger primes in real-world scenarios
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randint(2, phi - 1)
    while math.gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Calculate d, the modular multiplicative inverse of e (d * e % phi = 1)
    d = pow(e, -1, phi)

    return ((e, n), (d, n))


def blind_sign_message(message, private_key):
    # Blind sign a message using RSA
    m = int(hashlib.sha256(str(message).encode()).hexdigest(), 16)
    return pow(m, private_key[0], private_key[1])


def main():
    # Simulate the election process with 2 candidates and 4 voters
    candidates = {1: "Candidate A", 2: "Candidate B"}
    voters = []

    # Generate RSA key pairs for voters and authority
    authority_keypair = generate_rsa_keypair()
    for i in range(4):
        voters.append({
            'id': i + 1,
            'keypair': generate_rsa_keypair(),
            'vote': None
        })

    # Voting phase
    for voter in voters:
        candidate_id = random.choice(list(candidates.keys()))
        # Blind the vote
        blinded_vote = pow(candidate_id, voter['keypair'][0][0], voter['keypair'][0][1])
        # Sign the blinded vote
        signed_blind_vote = blind_sign_message(blinded_vote, authority_keypair[1])
        # Store the blinded and signed vote
        voter['vote'] = (blinded_vote, signed_blind_vote)

    # Tally the votes
    tally = {candidate: 0 for candidate in candidates.values()}
    for voter in voters:
        for candidate_id, candidate_name in candidates.items():
            # Unblind the vote
            unblinded_vote = pow(voter['vote'][0], voter['keypair'][1][0],
                                 voter['keypair'][1][1])
            if unblinded_vote == candidate_id:
                # Verify the signature before counting the vote
                hashed_vote = hashlib.sha256(str(voter['vote'][0]).encode()).hexdigest()
                if pow(voter['vote'][1], authority_keypair[0][0],
                       authority_keypair[0][1]) == int(hashed_vote, 16):
                    tally[candidate_name] += 1

    # Display the results
    print("Election Results:")
    for candidate, votes in tally.items():
        print(f"{candidate}: {votes} votes")


if __name__ == "__main__":
    main()
