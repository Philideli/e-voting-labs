from Crypto.Util import number
from Crypto.PublicKey import ElGamal
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random
import hashlib

class Voter:
    def __init__(self, voter_id, token, public_key):
        self.voter_id = voter_id
        self.token = token
        self.public_key = public_key

    def vote(self, candidate):
        # Етап голосування
        bulletin = self.generate_bulletin(candidate)
        encrypted_bulletin = self.encrypt_bulletin(bulletin, self.public_key)
        return encrypted_bulletin

    def generate_bulletin(self, candidate):
        # Генерація бюлетеня
        bulletin = f"{self.voter_id} votes for {candidate}"
        return bulletin

    def encrypt_bulletin(self, bulletin, public_key):
        # Шифрування бюлетеня
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_bulletin = cipher.encrypt(bulletin.encode())
        return encrypted_bulletin

class VotingAuthority:
    def __init__(self, num_voters):
        self.voters = []
        self.generate_keys(num_voters)

    def generate_keys(self, num_voters):
        # Генерація ключів для виборців
        for i in range(num_voters):
            key = ElGamal.generate(2048, Random.new().read)
            self.voters.append({"id": i, "public_key": key.publickey(), "private_key": key})

    def get_voter_token(self, voter_id):
        # Отримання токену для виборця
        voter = next((v for v in self.voters if v["id"] == voter_id), None)
        return {"id": voter["id"], "public_key": voter["public_key"]}

class ElectionCommission:
    def __init__(self):
        self.votes = {}

    def collect_votes(self, encrypted_votes):
        # Збір голосів
        for encrypted_vote in encrypted_votes:
            voter_id = encrypted_vote["voter_id"]
            vote = self.decrypt_vote(encrypted_vote)
            self.votes[voter_id] = vote

    def decrypt_vote(self, encrypted_vote):
        # Розшифрування голосу
        voter_id = encrypted_vote["voter_id"]
        voter_public_key = encrypted_vote["voter_public_key"]
        encrypted_bulletin = encrypted_vote["encrypted_bulletin"]

        voter = next((v for v in VotingAuthority.voters if v["id"] == voter_id), None)
        private_key = voter["private_key"]

        cipher = PKCS1_OAEP.new(private_key)
        decrypted_bulletin = cipher.decrypt(encrypted_bulletin).decode()

        return {"voter_id": voter_id, "vote": decrypted_bulletin}

    def publish_results(self):
        # Оголошення результатів
        print("Election Results:")
        for voter_id, vote in self.votes.items():
            print(f"Voter {voter_id}: Voted for {vote['vote']}")

def main():
    # Ініціалізація органів
    authority = VotingAuthority(num_voters=4)
    commission = ElectionCommission()

    # Реєстрація виборців та отримання токенів
    voter_tokens = [authority.get_voter_token(i) for i in range(4)]
    
    # Голосування виборців
    encrypted_votes = []
    for token in voter_tokens:
        voter = Voter(voter_id=token["id"], token=token, public_key=token["public_key"])
        encrypted_vote = voter.vote(candidate="Candidate1")
        encrypted_votes.append({"voter_id": voter.voter_id, "voter_public_key": voter.public_key, "encrypted_bulletin": encrypted_vote})

    # Збір голосів та оголошення результатів
    commission.collect_votes(encrypted_votes)
    commission.publish_results()

main()
