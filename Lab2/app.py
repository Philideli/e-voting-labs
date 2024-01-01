from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class Voter:
    def __init__(self, name, id, has_voted=False):
        self.name = name
        self.has_voted = has_voted
        self.election_vote = None
        self.voter_id = id
        self.masked_messages = None  # To store the masked (encrypted) messages
        self.signed_messages = None  # To store the signed messages received from the Election Authority
        # A random masking factor r
        self.r = 5

    def generate_messages(self, candidates):
        messages = []
        for i in range(1, 11):
            batch = []
            for candidate in candidates:
                message = candidate.id
                batch.append(message)
            messages.append(batch)
        return messages

    def mask_messages(self, candidates, public_key):
        self.masked_messages = [self.mask_message(message, public_key) for message in
                                self.generate_messages(candidates)]

    def mask_message(self, message: list[str], public_key: bytes) -> list[int]:
        masked_values = []
        for m in message:
            key = RSA.import_key(public_key).public_key()
            message_bytes = m.encode('utf-8')

            # Calculate the masked value: (m * r) ^ e mod n
            m_r = int.from_bytes(message_bytes, 'big') * self.r
            masked_value = pow(m_r, key.e, key.n) % key.n
            masked_values.append(masked_value)
        return masked_values

    def receive_signed_messages(self, signed_messages, public_key):
        key = RSA.import_key(public_key).public_key()
        self.signed_messages = [s * pow(self.r, -1) % key.n for s in signed_messages]

    def choose_and_encrypt_ballot(self, choice, public_key):
        key = RSA.import_key(public_key).public_key()
        chosen_ballot = None
        for s in self.signed_messages:
            if s == choice:
                chosen_ballot = str(s)
                break
        cipher = PKCS1_OAEP.new(key)
        encrypted_ballot = cipher.encrypt(chosen_ballot.encode())
        return encrypted_ballot

    def decrypt_ballot(self, encrypted_ballot, private_key):
        cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
        decrypted_ballot = cipher.decrypt(encrypted_ballot)
        return decrypted_ballot.decode()

    def send_encrypted_ballot(self, authority):
        # Simulating sending the chosen and encrypted ballot to EA
        chosen_ballot = self.choose_and_encrypt_ballot(self.election_vote,
                                                       authority.public_key)
        authority.receive_encrypted_ballot(chosen_ballot, self.voter_id)

    def prepare_for_voting(self, authority, candidates):
        self.mask_messages(candidates, authority.public_key)
        self.send_encrypted_messages(authority)


    def vote(self, candidates, authority):
        if not self.has_voted:
            print(f"{self.name}, choose a candidate:")
            for i, candidate in enumerate(candidates, start=1):
                print(f"{i}. {candidate.id}")
            choice = int(input())
            if 1 <= choice <= len(candidates):
                self.election_vote = choice
                self.send_encrypted_ballot(authority)
                self.has_voted = True
                print("Vote recorded.")
            else:
                print("Invalid choice. Spoiled ballot.")
        else:
            print(f"{self.name}, already voted.")

    def send_encrypted_messages(self, authority):
        authority.receive_masked_messages(self.masked_messages, self)

class Candidate:
    def __init__(self, id):
        self.id = id
        self.votes = 0


class ElectionAuthority:
    def __init__(self, voters=[], candidates=[]):
        key = RSA.generate(2048)
        self.private_key = key.export_key()
        self.public_key = key.publickey().export_key()
        self.votes = []
        self.candidates = candidates
        self.voters = voters
        self.registered_voters = set()  # To keep track of registered voters

    def receive_masked_messages(self, masked_messages: list[int], voter):
        # Simulating receiving masked messages from a voter
        voter_id = voter.voter_id
        if voter_id not in self.registered_voters:
            self.registered_voters.add(voter_id)
            self.send_signed_messages(masked_messages, voter)
        else:
            print("Duplicate voter ID. Ignoring the messages.")

    def send_signed_messages(self, masked_messages, voter):
        # EA signs 1 out of 10 masked messages
        signatures = []
        for i in range(len(masked_messages[0])):
            message = masked_messages[0][i]
            key = RSA.import_key(self.private_key)
            signature = pow(message, key.d) % key.n
            signatures.append(signature)
        voter.receive_signed_messages(signatures, self.public_key)
        print(f"Signed messages sent to {voter.voter_id}.")

    def receive_encrypted_ballot(self, encrypted_ballot, voter_id):
        decrypted_ballot = self.decrypt_ballot(encrypted_ballot, self.private_key)
        # check if already voted
        for vote in self.votes:
            if vote[1] == voter_id:
                print(f"{voter_id} already voted! Ignoring duplicated vote ")
                return
        self.votes.append((decrypted_ballot, voter_id))
        print(f"Received encrypted ballot from {voter_id}: {decrypted_ballot}")

    def decrypt_ballot(self, encrypted_ballot, private_key):
        cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
        decrypted_ballot = cipher.decrypt(encrypted_ballot)
        print(decrypted_ballot.decode())
        return decrypted_ballot.decode()

    def calculate_results(self):
        # Counting votes and publishing results
        print("Voting Results:")
        for vote in self.votes:
            decrypted_ballot = vote[0]
            if decrypted_ballot.isdigit() and 1 <= int(decrypted_ballot) <= len(self.candidates):
                candidate_index = int(decrypted_ballot)
                candidate_name = self.candidates[candidate_index - 1].id
                print(f"{vote[1]} voted for {candidate_name}")
                # Increment the candidate's vote count
                self.candidates[candidate_index - 1].votes += 1  # Uncomment this line in a real implementation
            else:
                print("Invalid ballot. Ignoring vote.")

        for candidate in self.candidates:
            print(f"{candidate.id}: {candidate.votes} votes.")

    def election(self):
        # Voting process
        for voter in self.voters:
            voter.prepare_for_voting(self, self.candidates)
            voter.vote(self.candidates, self)


def main():
    # Candidates and Voters
    candidates = [Candidate("Candidate1"), Candidate("Candidate2")]
    voters = [Voter("Luke", "Voter1"), Voter("Lea", "Voter2"), Voter("Ben", "Voter3"),
              Voter("R2D2", "Voter4")]

    # Election Authority
    authority = ElectionAuthority(voters=voters, candidates=candidates)

    # Start the election
    authority.election()

    # Calculate and print results
    authority.calculate_results()


if __name__ == "__main__":
    main()
