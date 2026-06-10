const ort = require('onnxruntime-node');

async function test() {
    try {
        const session = await ort.InferenceSession.create('models/phishguard_edge.onnx');
        const feeds = {};
        feeds[session.inputNames[0]] = new ort.Tensor('float32', new Float32Array(40), [1, 40]);
        console.log("Running session...");
        const results = await session.run(feeds);
        console.log("Success!");
        console.log("Results keys:", Object.keys(results));
        const probOutput = results[session.outputNames[1]];
        console.log("Prob output type:", probOutput.type);
        console.log("Prob output data:", probOutput.data);
    } catch (e) {
        console.error("Error:", e);
    }
}
test();
