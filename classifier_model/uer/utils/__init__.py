from uer.utils.tokenizers import CharTokenizer
from uer.utils.tokenizers import SpaceTokenizer
from uer.utils.tokenizers import BertTokenizer
from uer.utils.act_fun import gelu, gelu_fast, relu, silu, linear


str2tokenizer = {"char": CharTokenizer, "space": SpaceTokenizer, "bert": BertTokenizer}

str2act = {"gelu": gelu, "gelu_fast": gelu_fast, "relu": relu, "silu": silu, "linear": linear}

__all__ = [
    "CharTokenizer", "SpaceTokenizer", "BertTokenizer", "str2tokenizer",
    "gelu", "gelu_fast", "relu", "silu", "linear", "str2act",
]
