---
pretty_name: CodeSecEval
language:
- en
task_categories:
- text-generation
tags:
- code-generation
- secure-code-generation
- insecure-code-repair
- software-security
- cwe
- python
- program-synthesis
- benchmark
size_categories:
- n<1K
configs:
- config_name: CodeSecEval
  data_files:
  - split: test
    path:
    - data/SecEvalBase/test.jsonl
    - data/SecEvalPlus/test.jsonl

- config_name: SecEvalBase
  data_files:
  - split: test
    path: data/SecEvalBase/test.jsonl

- config_name: SecEvalPlus
  data_files:
  - split: test
    path: data/SecEvalPlus/test.jsonl
---

# CodeSecEval

CodeSecEval is an execution-based benchmark for evaluating large language models on secure code generation and insecure-code repair.

The benchmark contains 255 Python programming tasks spanning 77 CWE vulnerability categories. Each task provides a problem specification, an insecure implementation, a secure reference implementation, executable tests, and an entry point.

## Dataset Subsets

This repository contains two subsets:

- **SecEvalBase**: 115 tasks derived from SecurityEval and augmented with secure reference implementations, executable tests, functional/security test splits, and entry points.
- **SecEvalPlus**: 140 newly constructed tasks focusing on high-impact CWE categories, mainly using natural-language task descriptions.

A combined configuration, **CodeSecEval**, is also provided for loading the full benchmark.

## Dataset Structure

```text
CodeSecEval/
├── data/
│   ├── SecEvalBase/
│   │   └── test.jsonl
│   └── SecEvalPlus/
│       └── test.jsonl
├── notebooks/
│   └── Compute_SecureCode_Pass_Rates_CodeSecEval.ipynb
└── README.md
```

## Data Fields

Each example preserves the original field names and contains the following fields:

- `ID`: Unique task identifier, such as `CWE-502_codeql_1.py` or `CWE-20_01`.
- `Problem`: Problem description or code-form prompt.
- `Insecure Code`: Vulnerable implementation.
- `Secure Code`: Secure reference implementation.
- `Test`: Canonical executable test suite, usually defined as a `check(candidate)` function.
- `Test-FP`: Auxiliary functional-only test suite.
- `Test-SP`: Auxiliary security-oriented test suite.
- `Entry_Point`: Name of the target function to implement.

Both `SecEvalBase` and `SecEvalPlus` use the same field schema above.

## Loading the Dataset

```python
from datasets import load_dataset

repo = "JasonWang1/CodeSecEval"

dataset = load_dataset(repo, "CodeSecEval", split="test")
base = load_dataset(repo, "SecEvalBase", split="test")
plus = load_dataset(repo, "SecEvalPlus", split="test")

print(len(dataset))  # 255
print(len(base))     # 115
print(len(plus))     # 140
```

## Example

```python
example = plus[0]

print(example["ID"])
print(example["Entry_Point"])
print(example["Problem"])
```

## Intended Use

CodeSecEval is intended for research on:

- secure code generation;
- insecure-code repair;
- vulnerability-aware program synthesis;
- execution-based evaluation of generated code;
- measuring functional correctness and security robustness of LLM-generated programs.

The `Problem` field can be used as the prompt for secure code generation. The `Insecure Code` field can be used as the input for insecure-code repair. The `Secure Code` field provides a reference implementation.

## Evaluation

The `Test` field is the canonical executable test suite for each task. It contains both functional and security-relevant assertions.

A generated solution should pass the tests in `Test` to be considered successful for the corresponding task. The `Test-FP` and `Test-SP` fields are provided as auxiliary split test suites for evaluating functional correctness and security robustness separately.

Users who conduct separate F-Pass@1 and S-Pass@1 evaluation should verify the auxiliary split tests in their local evaluation environment before reporting results.

## Basic Evaluation Pattern

The following simplified example illustrates how to execute a generated candidate against a task test:

```python
def run_task_test(example, candidate_function):
    namespace = {}
    exec(example["Test"], namespace)
    check = namespace["check"]
    check(candidate_function)
```

For safe and reproducible evaluation, generated code should be executed in an isolated environment with appropriate timeouts and resource limits.

## Evaluation Notebook

We provide a supplementary notebook for reproducing pass-rate statistics:

```text
notebooks/Compute_SecureCode_Pass_Rates_CodeSecEval.ipynb
```

The notebook can be used to run the reference `Secure Code` implementations against the provided tests and compute pass rates for:

- the full canonical test suite in `Test`;
- the functional-only split in `Test-FP`;
- the security-oriented split in `Test-SP`.

To use the notebook, clone or download this repository, install the required Python packages, and launch Jupyter from the repository root. Then open:

```text
notebooks/Compute_SecureCode_Pass_Rates_CodeSecEval.ipynb
```

If you run the notebook from a different working directory, update the dataset path variables in the first code cell so that they point to:

```text
data/SecEvalBase/test.jsonl
data/SecEvalPlus/test.jsonl
```

## Important Security Notice

This dataset contains intentionally vulnerable code snippets for research and evaluation purposes. Do not copy `Insecure Code` into production systems.

Some examples may include placeholder strings that resemble API keys, tokens, file paths, or other sensitive values. These strings are included only to model vulnerability patterns such as hard-coded credentials and should not be treated as real secrets.

## License

The license is currently under review. SecEvalBase is derived from SecurityEval, whose original repository and Hugging Face dataset page do not appear to provide an explicit license.

## Citation

If you use this dataset, please cite the accompanying paper:

```bibtex
@inproceedings{codesec_eval_2026,
  title = {Toward Secure Code Generation: Bridging Correctness and Security via Task-Adaptive Vulnerability Modeling and Execution-Based Benchmarking},
  author = {Wang, Jiexin and Cao, Liuwen and Luo, Xitong and Cao, Yang and Li, Zhenghao and Xiao, Yunyi and Zhao, Mengchen and Jatowt, Adam and Cai, Yi},
  booktitle = {Proceedings of the ACM International Symposium on Software Testing and Analysis},
  year = {2026}
} 
```