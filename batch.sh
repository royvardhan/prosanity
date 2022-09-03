set -e
pubkey="0x04a07d161548d388c2a9713c41c7a691f32e3b4f88a0e073ecb617d85087475c6a820f819b95a2bc5134c04042c3122bc518d3512a09ba310df7409a8575bc882d"
token="TELGRAM_BOT_TOKEN"
id="TELGRAM_CHAT_ID"
profanity_arg="-token $token -id $id -pubkey $pubkey"

for i in {0..15}; do
    profanity $profanity_arg -start $i -start-batch 0 -max-batch 200
done

for i in {0..15}; do
    profanity $profanity_arg -start $i -start-batch 200 -max-batch 1024
done

for i in {0..15}; do
    profanity $profanity_arg -start $i -start-batch 1024 -max-batch 2048
done
