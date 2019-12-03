"""
By convention, we move eol'd gates into this module to keep them separated and avoid naming conflicts for classes.

"""
from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger, LifecycleStates


class SuidModeDiffTrigger(BaseTrigger):
    __trigger_name__ = 'suidmodediff'
    __description__ = 'triggers if file is suid, but mode is different between the image and its base'
    __lifecycle_state__ = LifecycleStates.eol


class SuidFileAddTrigger(BaseTrigger):
    __trigger_name__ = 'suidfileadd'
    __description__ = 'triggers if the evaluated image has a file that is SUID and the base image does not'
    __lifecycle_state__ = LifecycleStates.eol


class SuidFileDelTrigger(BaseTrigger):
    __trigger_name__ = 'suidfiledel'
    __description__ = 'triggers if the base image has a SUID file, but the evaluated image does not'
    __lifecycle_state__ = LifecycleStates.eol


class SuidDiffTrigger(BaseTrigger):
    __trigger_name__ = 'suiddiff'
    __description__ = 'triggers if any one of the other events for this gate have triggered'
    __lifecycle_state__ = LifecycleStates.eol


class SuidDiffGate(Gate):
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = 'suiddiff'
    __description__ = 'SetUID File Checks'
    __triggers__ = [
        SuidDiffTrigger,
        SuidFileAddTrigger,
        SuidFileDelTrigger,
        SuidModeDiffTrigger
    ]


class BaseOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'baseoutofdate'
    __description__ = 'triggers if the image\'s base image has been updated since the image was built/analyzed'
    __params__ = {}
    __lifecycle_state__ = LifecycleStates.eol


class ImageCheckGate(Gate):
    __gate_name__ = 'imagecheck'
    __description__ = 'Checks on image ancestry'
    __triggers__ = [BaseOutOfDateTrigger]
    __lifecycle_state__ = LifecycleStates.eol


class PkgDiffTrigger(BaseTrigger):
    __trigger_name__ = 'pkgdiff'
    __description__ = 'triggers if any one of the other events has triggered'
    __lifecycle_state__ = LifecycleStates.eol


class PkgVersionDiffTrigger(BaseTrigger):
    __trigger_name__ = 'pkgversiondiff'
    __description__ = 'triggers if the evaluated image has a package installed with a different version of the same package from a previous base image'
    __lifecycle_state__ = LifecycleStates.eol


class PkgAddTrigger(BaseTrigger):
    __trigger_name__ = 'pkgadd'
    __description__ = 'triggers if image contains a package that is not in its base'
    __lifecycle_state__ = LifecycleStates.eol


class PkgDelTrigger(BaseTrigger):
    __trigger_name__ = 'pkgdel'
    __description__ = 'triggers if image has removed a package that is installed in its base'
    __lifecycle_state__ = LifecycleStates.eol


class PkgDiffGate(Gate):
    __lifecycle_state__ = LifecycleStates.eol
    __gate_name__ = 'pkgdiff'
    __description__ = 'Distro Package Difference Checks From Base Image'
    __triggers__ = [
        PkgVersionDiffTrigger,
        PkgAddTrigger,
        PkgDelTrigger,
        PkgDiffTrigger
    ]


class LowSeverityTrigger(BaseTrigger):
    __trigger_name__ = 'vulnlow'
    __description__ = 'Checks for "low" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Low']
    __lifecycle_state__ = LifecycleStates.eol


class MediumSeverityTrigger(BaseTrigger):
    __trigger_name__ = 'vulnmedium'
    __description__ = 'Checks for "medium" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Medium']
    __lifecycle_state__ = LifecycleStates.eol


class HighSeverityTrigger(BaseTrigger):
    __trigger_name__ = 'vulnhigh'
    __description__ = 'Checks for "high" severity vulnerabilities found in an image'
    __vuln_levels__ = ['High']
    __lifecycle_state__ = LifecycleStates.eol


class CriticalSeverityTrigger(BaseTrigger):
    __trigger_name__ = 'vulncritical'
    __description__ = 'Checks for "critical" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Critical']
    __lifecycle_state__ = LifecycleStates.eol


class UnknownSeverityTrigger(BaseTrigger):
    __trigger_name__ = 'vulnunknown'
    __description__ = 'Checks for "unkonwn" or "negligible" severity vulnerabilities found in an image'
    __vuln_levels__ = ['Unknown', 'Negligible', None]
    __lifecycle_state__ = LifecycleStates.eol


class FeedOutOfDateTrigger(BaseTrigger):
    __trigger_name__ = 'feedoutofdate'
    __description__ = 'Fires if the CVE data is older than the window specified by the parameter MAXAGE (unit is number of days)'
    __lifecycle_state__ = LifecycleStates.eol


class UnsupportedDistroTrigger(BaseTrigger):
    __trigger_name__ = 'unsupporteddistro'
    __description__ = 'Fires if a vulnerability scan cannot be run against the image due to lack of vulnerability feed data for the images distro'
    __lifecycle_state__ = LifecycleStates.eol


class AnchoreSecGate(Gate):
    __gate_name__ = 'anchoresec'
    __description__ = 'Vulnerability checks against distro packages'
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = 'vulnerabilities'

    __triggers__ = [
        LowSeverityTrigger,
        MediumSeverityTrigger,
        HighSeverityTrigger,
        CriticalSeverityTrigger,
        UnknownSeverityTrigger,
        FeedOutOfDateTrigger,
        UnsupportedDistroTrigger
    ]


class VerifyTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = 'verify'
    __description__ = 'Check package integrity against package db in in the image. Triggers for changes or removal or content in all or the selected DIRS param if provided, and can filter type of check with the CHECK_ONLY param'


class PkgNotPresentTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.eol
    __trigger_name__ = 'pkgnotpresent'
    __description__ = 'triggers if the package(s) specified in the params are not installed in the container image. The parameters specify different types of matches.',


class PackageCheckGate(Gate):
    __gate_name__ = 'pkgcheck'
    __description__ = 'Distro package checks'
    __lifecycle_state__ = LifecycleStates.eol
    __superceded_by__ = 'packages'
    __triggers__ = [
        PkgNotPresentTrigger,
        VerifyTrigger
    ]
