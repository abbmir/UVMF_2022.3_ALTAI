//----------------------------------------------------------------------
// Created with uvmf_gen version 2019.4_1
//----------------------------------------------------------------------
// pragma uvmf custom header begin
// pragma uvmf custom header end
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//     
// PACKAGE: This file defines all of the files contained in the
//    interface package that will run on the host simulator.
//
// CONTAINS:
//    - <alu_in_typedefs_hdl>
//    - <alu_in_typedefs.svh>
//    - <alu_in_transaction.svh>

//    - <alu_in_configuration.svh>
//    - <alu_in_driver.svh>
//    - <alu_in_monitor.svh>

//    - <alu_in_transaction_coverage.svh>
//    - <alu_in_sequence_base.svh>
//    - <alu_in_random_sequence.svh>

//    - <alu_in_responder_sequence.svh>
//    - <alu_in2reg_adapter.svh>
//
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//
package alu_in_pkg;
  
   import uvm_pkg::*;
   import uvmf_base_pkg_hdl::*;
   import uvmf_base_pkg::*;
   import alu_in_pkg_hdl::*;

   `include "uvm_macros.svh"

   // pragma uvmf custom package_imports_additional begin 
   // pragma uvmf custom package_imports_additional end

   `include "src/alu_in_macros.svh"
   
   export alu_in_pkg_hdl::*;
   
 

   // Parameters defined as HVL parameters

   `include "src/alu_in_typedefs.svh"
   `include "src/alu_in_transaction.svh"

   `include "src/alu_in_configuration.svh"
   `include "src/alu_in_driver.svh"
   `include "src/alu_in_monitor.svh"

   `include "src/alu_in_transaction_coverage.svh"
   `include "src/alu_in_sequence_base.svh"
   `include "src/alu_in_random_sequence.svh"

   `include "src/alu_in_responder_sequence.svh"
   `include "src/alu_in2reg_adapter.svh"

   `include "src/alu_in_agent.svh"

   // pragma uvmf custom package_item_additional begin
   `include "src/alu_in_directed_sequence.svh"
   `include "src/alu_in_and_sequence.svh"
   `include "src/alu_in_add_sequence.svh"
   `include "src/alu_in_mul_sequence.svh"
   `include "src/alu_in_xor_sequence.svh"


   // pragma uvmf custom package_item_additional end

endpackage

