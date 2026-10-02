import pytest
from benign_lab.clock_sync import estimate,verdict


def test_network_delay_does_not_look_like_clock_skew():
    # A symmetric 800ms network trip with 2s processing on the worker.
    sample=estimate(100,100.4,102.4,102.8)
    assert sample['offset_s']==pytest.approx(0)
    assert sample['round_trip_s']==pytest.approx(.8)
    assert verdict(sample,.25)=='inconclusive'
    # A fast followup sample certifies the same synchronized clock.
    assert verdict(estimate(100,100.01,100.02,100.03),.25)=='synchronized'


def test_real_clock_skew_is_rejected():
    for shift in (-1,1):
        sample=estimate(100,100.01+shift,100.02+shift,100.03)
        assert sample['offset_s']==pytest.approx(shift)
        assert verdict(sample,.25)=='skewed'


def test_asymmetric_delay_is_not_falsely_reported_as_ntp_failure():
    sample=estimate(100,100.7,100.7,100.72)
    assert verdict(sample,.25)=='inconclusive'


def test_invalid_timestamps_are_rejected():
    with pytest.raises(ValueError):estimate(100,102,101,103)
    with pytest.raises(ValueError):estimate(100,float('nan'),101,103)
