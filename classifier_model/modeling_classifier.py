"""
Minimal classifier model definition for ET-BERT inference.
"""

import torch
import torch.nn as nn

from uer.layers import str2embedding
from uer.encoders import str2encoder


class Classifier(nn.Module):
    """
    Classification head used by finetuned ET-BERT models.
    """

    def __init__(self, args):
        super().__init__()
        self.embedding = str2embedding[args.embedding](args, len(args.tokenizer.vocab))
        self.encoder = str2encoder[args.encoder](args)
        self.labels_num = args.labels_num
        self.pooling = args.pooling
        self.output_layer_1 = nn.Linear(args.hidden_size, args.hidden_size)
        self.output_layer_2 = nn.Linear(args.hidden_size, self.labels_num)

    def forward(self, src, tgt, seg, soft_tgt=None):
        emb = self.embedding(src, seg)
        output = self.encoder(emb, seg)

        if self.pooling == "mean":
            output = torch.mean(output, dim=1)
        elif self.pooling == "max":
            output = torch.max(output, dim=1)[0]
        elif self.pooling == "last":
            output = output[:, -1, :]
        else:
            output = output[:, 0, :]

        output = torch.tanh(self.output_layer_1(output))
        logits = self.output_layer_2(output)
        return None, logits

