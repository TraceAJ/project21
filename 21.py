import time
import hashlib
import random
import math

class SchnorrBatch:
    def __init__(self, messages, private_keys):
        self.messages = messages
        self.private_keys = private_keys
        self.public_keys = []
        self.challenges = []
        self.responses = []


    def generate_keys(self):
        for private_key in self.private_keys:
            public_key = self.__generate_public_key(private_key)
            self.public_keys.append(public_key)

    def sign_messages(self):
        for i in range(len(self.messages)):
            challenge = self.__generate_challenge()
            response = self.__generate_response(challenge, self.private_keys[i])
            self.challenges.append(challenge)
            self.responses.append(response)

    def verify_signatures(self):
        for i in range(len(self.messages)):
            if not self.__verify_signature(self.messages[i], self.challenges[i],
                                           self.responses[i], self.public_keys[i]):
                return False
        return True

    def __generate_public_key(self, private_key):
        return hashlib.sha256(str(private_key).encode()).hexdigest()

    def __generate_challenge(self):
        return random.randint(0, 2**256-1)

    def __generate_response(self, challenge, private_key):
        return (private_key + challenge) % (2**256)

    def __verify_signature(self, message, challenge, response, public_key):
        computed_public_key = self.__generate_public_key(response)
        return computed_public_key == public_key and self.__generate_challenge() == challenge

# 测试代码
def test():
    start_time = time.time()
    messages = ['message1', 'message2', 'message3']
    private_keys = [123, 456, 789]
    schnorr_batch = SchnorrBatch(messages, private_keys)
    schnorr_batch.generate_keys()
    schnorr_batch.sign_messages()
    result = schnorr_batch.verify_signatures()
    end_time = time.time()
    execution_time = (end_time - start_time)
    print('签名验证结果:', result)
    print('代码运行时间: %.4f秒' % execution_time)
test()
