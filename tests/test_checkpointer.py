"""SubTrajectory 文件名消毒测试"""
from depsafe.checkpointer import SubTrajectory


def test_sub_task_name_sanitizes_path_separators(tmp_path):
    traj = SubTrajectory(
        project_root=tmp_path,
        sub_task_name="explore task on ./app.py for non-call vulns",
    )
    traj.save([], {"token": {}}, status="completed")
    files = list((tmp_path / ".depsafe" / "sub_trajectories").glob("*.json"))
    assert len(files) == 1
    assert "/" not in files[0].name
