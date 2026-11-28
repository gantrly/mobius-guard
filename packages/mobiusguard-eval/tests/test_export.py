"""Which MatMuls ``int8-ffn2-float`` keeps in float32 (decision 0024)."""

from __future__ import annotations

from typing import Any

import numpy as np
import pytest
from mobiusguard_eval.export import QUANTIZE, export, float_matmuls

onnx = pytest.importorskip("onnx")
helper, numpy_helper = onnx.helper, onnx.numpy_helper

HIDDEN, INTERMEDIATE = 4, 8


def _layer(names: tuple[str, ...] = ("q", "scores", "ffn1", "gelu", "ffn2")) -> Any:
    """One layer's shape: a projection, an activation-by-activation MatMul (attention
    scores), then the feed-forward pair with GELU between."""
    w = {
        "w_q": np.ones((HIDDEN, HIDDEN), np.float32),
        "w_ffn1": np.ones((HIDDEN, INTERMEDIATE), np.float32),
        "w_ffn2": np.ones((INTERMEDIATE, HIDDEN), np.float32),
    }
    q, scores, ffn1, gelu, ffn2 = names
    nodes = [
        helper.make_node("MatMul", ["x", "w_q"], ["h"], name=q),
        helper.make_node("MatMul", ["h", "x_t"], ["s"], name=scores),
        helper.make_node("MatMul", ["h", "w_ffn1"], ["f"], name=ffn1),
        helper.make_node("Relu", ["f"], ["g"], name=gelu),
        helper.make_node("MatMul", ["g", "w_ffn2"], ["y"], name=ffn2),
    ]
    graph = helper.make_graph(
        nodes, "layer",
        [helper.make_tensor_value_info("x", onnx.TensorProto.FLOAT, [1, HIDDEN]),
         helper.make_tensor_value_info("x_t", onnx.TensorProto.FLOAT, [HIDDEN, 1])],
        [helper.make_tensor_value_info("y", onnx.TensorProto.FLOAT, [1, HIDDEN]),
         helper.make_tensor_value_info("s", onnx.TensorProto.FLOAT, [1, 1])],
        [numpy_helper.from_array(v, k) for k, v in w.items()],
    )  # fmt: skip
    return helper.make_model(graph)


def test_keeps_the_second_feed_forward_and_activation_matmuls() -> None:
    assert float_matmuls(_layer(), INTERMEDIATE) == ["scores", "ffn2"]


def test_quantises_every_weight_matmul_when_no_weight_is_that_tall() -> None:
    assert float_matmuls(_layer(), 99) == ["scores"]


def test_refuses_unnamed_nodes() -> None:
    """The quantiser excludes nodes by name, so an unnamed node would silently be quantised."""
    with pytest.raises(ValueError, match="unnamed or repeated"):
        float_matmuls(_layer(("q", "", "ffn1", "gelu", "ffn2")), INTERMEDIATE)
    with pytest.raises(ValueError, match="unnamed or repeated"):
        float_matmuls(_layer(("q", "q", "ffn1", "gelu", "ffn2")), INTERMEDIATE)


def test_an_unknown_mode_is_refused(tmp_path: Any) -> None:
    assert QUANTIZE == ("int8", "int8-ffn2-float")
    with pytest.raises(ValueError, match="quantize must be one of"):
        export(tmp_path, tmp_path / "out", quantize="int4")
