# Disclaimer

This repository exists for **learning and defense**.

The goal is to give the security community detection rules, network captures and technical analysis it can build defenses on. Every piece of research here is about understanding an attack in order to stop it.

## Why PoCs exist here

Proof-of-concept code is included only to **fully reproduce each vulnerability** in a controlled lab. Faithful reproduction is needed to:

- analyze the attack path accurately
- assess the real-world impact honestly
- write detection rules that match real attack traffic, not guesses
- confirm that the fix removes the vulnerability

Without a working reproduction, detection rules are speculation and impact claims are unverified.

## Detection rules

The detection rules in this repository are provided **for education only**. They are not production-ready signatures. At most they have been tested against the research capture and one benign sample, nothing more.

If you use them anyway, you do so **at your own risk**. Before putting any rule into a security product:

- review the rule logic against your environment
- test it against your own traffic for false positives
- measure its performance impact on your detection pipeline
- adapt thresholds and conditions to your deployment

## No warranty, no liability

**Everything in this repository is provided "as is", without warranty of any kind**, express or implied. That covers the code, PoCs, labs, network captures, detection rules, evidence and write-ups alike. You use any of it at your own risk.

The author is not liable for any damage or loss that results from using this material. That includes crashed or corrupted systems, data loss, false positives, missed detections and any operational impact. Responsibility lies with whoever runs or deploys it, not with this repository or its author.

Several PoCs crash their target on purpose, and the kernel PoCs crash the kernel they run against. Run the labs in a disposable virtual machine or container, never on a system you depend on.

## Responsible use

Do not use any material in this repository against systems you do not own or do not have explicit written authorization to test. Unauthorized access to computer systems is illegal in most jurisdictions.
