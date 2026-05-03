# Standalone Inference

这个目录是一个完全自包含的 ET-BERT 推理模块，不再依赖父级 `ET-BERT/` 项目的任何代码。把整个文件夹拷到任何位置都能直接运行。

## 目录结构

```
standalone_inference/
├── generate_infer_dataset.py   # 把 pcap/pcapng 转成推理 TSV
├── run_classifier_infer.py     # 加载训练好的模型并输出预测
├── modeling_classifier.py      # 推理用的 Classifier 模型结构
├── packet_features.py          # 包级特征提取（默认 / window_payload 模式用）
├── flow_features.py            # 流级特征提取（flow 模式用，按需加载 scapy / flowcontainer）
├── models/                     # 词表与模型文件目录
└── uer/                        # 推理需要的 UER 子模块（已剥离训练 / 数据加载相关代码）
```

## 1) 从外部 pcap 生成推理数据（包级）

```bash
python standalone_inference/generate_infer_dataset.py ^
  --input_path classifier_model/assets/data/web1 ^
  --output_dir classifier_model/assets/data/web1 ^
  --dataset_level packet ^
  --feature_mode window_payload ^
  --window_payload_packets 5 ^
  --window_payload_stride 25 ^
  --payload_length 128 ^
  --max_records_per_capture 1500
```

## 2) 用训练好的模型推理

```bash
python standalone_inference/run_classifier_infer.py ^
  --load_model_path models/best_model.bin ^
  --vocab_path models/encryptd_vocab.txt ^
  --test_path classifier_model/assets/data/web1/nolabel_infer_dataset.tsv ^
  --prediction_path classifier_model/assets/data/web1/prediction.tsv ^
  --labels_num 5 ^
  --embedding word_pos_seg ^
  --encoder transformer ^
  --mask fully_visible ^
  --seq_length 128 ^
  --batch_size 64 ^
  --output_prob
```

## 输出和输出文件
- 打印概率前2的类别和对应概率
- `infer_dataset.tsv` / `nolabel_infer_dataset.tsv`：推理数据（带 / 不带占位 label 列）
- `infer_manifest.tsv`：每条样本对应的原始 pcap 路径
- `prediction.tsv`：
  - `label`：预测类别 id
  - `prob`（可选）：各类别概率，由 `--output_prob` 控制
  - `logits`（可选）：原始 logits，由 `--output_logits` 控制

## 依赖

- 推理脚本：`torch`
- pcap 预处理（包级 / window_payload）：`scapy`
- 流级模式额外需要：`flowcontainer`、SplitCap 工具、`editcap`（仅当输入是 pcapng 时）

`flow_features.py` 里的 scapy / flowcontainer 是按需加载的，如果只用包级模式就不必安装它们。
