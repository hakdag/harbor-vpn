"""Offline lab regression evidence; no credentials, privileged ports or external I/O."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

repo = Path(__file__).resolve().parents[2]
fixture = bytes.fromhex((repo / 'src/crates/ikev2-core/tests/fixtures/request.hex').read_text())
build = subprocess.run(['cargo', 'build', '--locked', '-p', 'ikev2d'], cwd=repo / 'src', capture_output=True)
if build.returncode:
    raise RuntimeError(build.stderr.decode())
with tempfile.TemporaryDirectory(prefix='m2-probe-') as folder:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
        first.bind(('127.0.0.1', 0))
        second.bind(('127.0.0.1', 0))
        port, natt = first.getsockname()[1], second.getsockname()[1]
    config = Path(folder) / 'lab.toml'
    config.write_text(f'[udp]\nike = "127.0.0.1:{port}"\nnatt = "127.0.0.1:{natt}"\n')
    with (Path(folder) / 'daemon.log').open('w+') as log:
        process = subprocess.Popen([str(repo / 'src/target/debug/ikev2d'), '--serve', str(config)], stdout=log, stderr=subprocess.STDOUT)
        results = []
        try:
            time.sleep(0.2)
            if process.poll() is not None:
                raise RuntimeError('daemon failed to bind')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                for critical in [False, True]:
                    packet = bytearray(fixture)
                    packet[:8] = (1001 + int(critical)).to_bytes(8, 'big')
                    offset = 28
                    while packet[offset] != 0:
                        offset += int.from_bytes(packet[offset + 2:offset + 4], 'big')
                    packet[offset] = 38
                    # CERTREQ: X.509 signature encoding, no CA restriction.
                    packet.extend(bytes([0, 128 if critical else 0, 0, 5, 4]))
                    packet[24:28] = len(packet).to_bytes(4, 'big')
                    client.sendto(packet, ('127.0.0.1', port))
                    response, _ = client.recvfrom(4096)
                    notify = int.from_bytes(response[34:36], 'big') if response[16] == 41 else None
                    results.append({'certreq_critical': critical, 'request_hex': packet.hex(), 'response_hex': response.hex(), 'response_sha256': hashlib.sha256(response).hexdigest(), 'first_payload': response[16], 'notify_type': notify, 'responder_spi_nonzero': any(response[8:16])})
        finally:
            process.terminate()
            status = process.wait(timeout=5)
            log.seek(0)
            daemon_log = log.read()
    assert results[0]['first_payload'] == 33 and results[0]['responder_spi_nonzero']
    assert results[1]['notify_type'] == 7
    output = {'build_exit': build.returncode, 'transport': 'unprivileged IPv4 loopback', 'daemon_exit_after_operator_SIGTERM': status, 'results': results, 'daemon_log': daemon_log}
    (Path(__file__).parent / 'protocol_probe.json').write_text(json.dumps(output, indent=2) + '\n')
