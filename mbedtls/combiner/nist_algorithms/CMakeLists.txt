#[[
    For configuring the settings add_definitions was used for the schemes
    which build directly with cmake. For those requiring running a makefile set some variables instead
    that get handled in the respective subfolder.
]]

# MAYO settings
add_definitions(
    -DMAYO_BUILD_TYPE_REF
)

#[[ 
    LESS settings
    NOTE: This is using the category 1 variant with highest performance 
    purely because the overall scheme performance is sloooow...
    This is done for now to keep frequent testing not an absolute nightmare.
    That being said it does not make me happy :)
]]
add_definitions(
    -DCATEGORY=252
    -DTARGET=45
    -DUSE_REFERENCE
)

# CROSS settings
add_definitions(
    -DRSDP
    -DCATEGORY_5
    -DSPEED
)

#[[ 
    QRUOV settings
    Note: I removed some lower end variants from the makescript to speed up the build,
    I don't think they will be needed but keep in mind for later
]]
set(QRUOV_OPTIMISATION "ref") # ref|avx2|avx512|portable64
set(QRUOV_CONFIG_H_GEN 1)
set(QRUOV_security_strength_category 5)
set(QRUOV_q 127)
set(QRUOV_L 3)
set(QRUOV_v 306)
set(QRUOV_m 105)
set(QRUOV_fc 1)
set(QRUOV_fe 1)
set(QRUOV_fc0 1)
set(QRUOV_PRG "a")

# SNOVA settings
set(SNOVA_V 60) # (V, O, L) = (60, 10, 4) -> NIST security level 5
set(SNOVA_O 10)
set(SNOVA_L 4)
set(SNOVA_SK_IS_SEED 0) # Use secret key as seed
set(SNOVA_OPTIMISATION 0) # 0 = Reference, 1 = General optimization, 2 = AVX2 Optimization 
set(SNOVA_PK_EXPAND_SHAKE 0) # Use SHAKE128 for public key expansion instead of AES-CTR(Disabled for now)

#[[ 
    UOV settings
    TODO: For some reason this doesn't build correctly with param > 3.
    The reason for this eludes me.
]]
set(UOV_PROJ ref)
set(UOV_VARIANT 1)
set(UOV_PARAM 3)

#SDITH settings
set(SDITH_VARIANT "Reference_Implementation") # ref|avx2 
set(SDITH_TYPE "Hypercube_Variant") # Threshhold_Variant|Hypercube_Variant
set(SDITH_SEC_LEVEL "cat5") # CAT_1|CAT_3|CAT_5
set(SDITH_FIELD "gf256") # GF256|P251

add_subdirectory(less)
add_subdirectory(cross)
add_subdirectory(snova)
add_subdirectory(mayo)
add_subdirectory(qruov)
add_subdirectory(uov)
add_subdirectory(sdith)
add_subdirectory(faest)

