from __future__ import annotations
import hashlib, json, math, time
from typing import Any
from aera_ml.evaluation.realdata import sha256_json
BATCH_SIZE = 64

def _model(torch: Any) -> Any:
    return torch.nn.Sequential(
        torch.nn.Flatten(),
        torch.nn.Linear(28 * 28, 512),
        torch.nn.ReLU(),
        torch.nn.Linear(512, 512),
        torch.nn.ReLU(),
        torch.nn.Linear(512, 10),
    )


def _state_dict_hash(torch: Any, model: Any) -> str:
    digest = hashlib.sha256()
    for name, tensor in sorted(model.state_dict().items()):
        value = tensor.detach().cpu().contiguous()
        digest.update(name.encode("utf-8"))
        digest.update(str(value.dtype).encode("ascii"))
        digest.update(json.dumps(list(value.shape), separators=(",", ":")).encode("ascii"))
        digest.update(value.numpy().tobytes(order="C"))
    return digest.hexdigest()


def _evaluate(torch: Any, model: Any, loader: Any, loss_fn: Any) -> dict[str, Any]:
    started = time.perf_counter()
    model.eval()
    total_loss = 0.0
    count = 0
    predictions: list[int] = []
    labels: list[int] = []
    with torch.no_grad():
        for inputs, targets in loader:
            logits = model(inputs)
            total_loss += float(loss_fn(logits, targets).item()) * int(targets.numel())
            count += int(targets.numel())
            predictions.extend(int(value) for value in logits.argmax(1).tolist())
            labels.extend(int(value) for value in targets.tolist())
    if count == 0:
        raise RuntimeError("empty evaluation loader")
    matrix = [[0 for _ in range(10)] for _ in range(10)]
    for truth, prediction in zip(labels, predictions, strict=True):
        matrix[truth][prediction] += 1
    recalls = {
        str(label): matrix[label][label] / sum(matrix[label]) if sum(matrix[label]) else 0.0
        for label in range(10)
    }
    result = {
        "accuracy": sum(int(left == right) for left, right in zip(labels, predictions, strict=True)) / count,
        "confusion_matrix": matrix,
        "evaluation_seconds": time.perf_counter() - started,
        "ground_truth_sha256": sha256_json(labels),
        "loss": total_loss / count,
        "per_class_recall": recalls,
        "prediction_sha256": sha256_json(predictions),
        "sample_count": count,
    }
    if not math.isfinite(result["loss"]):
        raise RuntimeError("non-finite evaluation loss")
    return result


def _loader(torch: Any, dataset: Any, indices: list[int], *, shuffle: bool, seed: int) -> Any:
    generator = torch.Generator().manual_seed(seed)
    return torch.utils.data.DataLoader(
        torch.utils.data.Subset(dataset, indices),
        batch_size=BATCH_SIZE,
        shuffle=shuffle,
        generator=generator,
        num_workers=0,
    )
