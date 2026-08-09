if(TARGET oc::libOTe)
  set(libOTe_FOUND TRUE)
  return()
endif()
find_package(Boost 1.74 REQUIRED COMPONENTS system thread)
set(_LOTE /root/simple-OPRF/voprf-bench/deps/libOTe)
set(_LB ${_LOTE}/out/build/linux)
set(_LI ${_LOTE}/out/install/linux)
set(_LP /root/simple-OPRF/voprf-bench/deps/local)
add_library(oc::KyberOT STATIC IMPORTED)
set_target_properties(oc::KyberOT PROPERTIES IMPORTED_LOCATION ${_LB}/thirdparty/KyberOT/libKyberOT.a)
add_library(oc::cryptoTools STATIC IMPORTED)
set_target_properties(oc::cryptoTools PROPERTIES IMPORTED_LOCATION ${_LB}/cryptoTools/cryptoTools/libcryptoTools.a
  INTERFACE_INCLUDE_DIRECTORIES "${_LOTE}/cryptoTools;${_LB}/cryptoTools;${_LI}/include;${_LP}/include")
add_library(oc::libOTe STATIC IMPORTED)
set_target_properties(oc::libOTe PROPERTIES IMPORTED_LOCATION ${_LB}/libOTe/liblibOTe.a
  INTERFACE_INCLUDE_DIRECTORIES "${_LOTE};${_LB};${_LB}/libOTe;${_LOTE}/out/coproto;${_LOTE}/out/macoro;${_LI}/include;${_LP}/include;${_LOTE}/thirdparty"
  INTERFACE_LINK_LIBRARIES "oc::cryptoTools;oc::KyberOT;${_LB}/coproto/coproto/libcoproto.a;${_LB}/macoro/macoro/libmacoro.a;${_LI}/lib/libsodium.a;${Boost_LIBRARIES}")
set(libOTe_FOUND TRUE)
