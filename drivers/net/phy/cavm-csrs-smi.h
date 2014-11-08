#ifndef __CAVM_CSRS_SMI__
#define __CAVM_CSRS_SMI__

union smix_en {
        uint64_t u64;
        struct smix_en_s {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t reserved_1_63                : 63;
        uint64_t en                           : 1;  /**< Interface enable
                                                         0=SMI Interface is down / no transactions, no MDC
                                                         1=SMI Interface is up */
#else
        uint64_t en                           : 1;
        uint64_t reserved_1_63                : 63;
#endif
        } s;
};
typedef union smix_en smix_en_t;

union smix_cmd {
        uint64_t u64;
        struct smix_cmd_s {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t reserved_18_63               : 46;
        uint64_t phy_op                       : 2;  /**< PHY Opcode depending on SMI_CLK[MODE]
                                                         SMI_CLK[MODE] == 0 (<=1Gbs / Clause 22)
                                                          x0=write
                                                          x1=read
                                                         SMI_CLK[MODE] == 1 (>1Gbs / Clause 45)
                                                          00=address
                                                          01=write
                                                          11=read
                                                          10=post-read-increment-address */
        uint64_t reserved_13_15               : 3;
        uint64_t phy_adr                      : 5;  /**< PHY Address */
        uint64_t reserved_5_7                 : 3;
        uint64_t reg_adr                      : 5;  /**< PHY Register Offset */
#else
        uint64_t reg_adr                      : 5;
        uint64_t reserved_5_7                 : 3;
        uint64_t phy_adr                      : 5;
        uint64_t reserved_13_15               : 3;
        uint64_t phy_op                       : 2;
        uint64_t reserved_18_63               : 46;
#endif
        } s;
};
typedef union smix_cmd smix_cmd_t;

union smix_rd_dat {
        uint64_t u64;
        struct smix_rd_dat_s {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t reserved_18_63               : 46;
        uint64_t pending                      : 1;  /**< Read Xaction Pending */
        uint64_t val                          : 1;  /**< Read Data Valid */
        uint64_t dat                          : 16; /**< Read Data */
#else
        uint64_t dat                          : 16;
        uint64_t val                          : 1;
        uint64_t pending                      : 1;
        uint64_t reserved_18_63               : 46;
#endif
        } s;
};
typedef union smix_rd_dat smix_rd_dat_t;

union smix_wr_dat {
        uint64_t u64;
        struct smix_wr_dat_s {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t reserved_18_63               : 46;
        uint64_t pending                      : 1;  /**< Write Xaction Pending */
        uint64_t val                          : 1;  /**< Write Data Valid */
        uint64_t dat                          : 16; /**< Write Data */
#else
        uint64_t dat                          : 16;
        uint64_t val                          : 1;
        uint64_t pending                      : 1;
        uint64_t reserved_18_63               : 46;
#endif
        } s;
};
typedef union smix_wr_dat smix_wr_dat_t;

union smix_clk {
        uint64_t u64;
        struct smix_clk_s {
#ifdef __BIG_ENDIAN_BITFIELD
        uint64_t reserved_25_63               : 39;
        uint64_t mode                         : 1;  /**< IEEE operating mode
                                                         0=Clause 22 complient
                                                         1=Clause 45 complient */
        uint64_t reserved_21_23               : 3;
        uint64_t sample_hi                    : 5;  /**< When to sample read data (extended bits) */
        uint64_t sample_mode                  : 1;  /**< Read Data sampling mode
                                                         According to the 802.3 spec, on reads, the STA
                                                         transitions MDC and the PHY drives MDIO with
                                                         some delay relative to that edge.  This is edge1.
                                                         The STA then samples MDIO on the next rising edge
                                                         of MDC.  This is edge2. Octeon can sample the
                                                         read data relative to either edge.
                                                          0=[SAMPLE_HI,SAMPLE] specify the sample time
                                                            relative to edge2
                                                          1=[SAMPLE_HI,SAMPLE] specify the sample time
                                                            relative to edge1 */
        uint64_t reserved_14_14               : 1;
        uint64_t clk_idle                     : 1;  /**< Do not toggle MDC on idle cycles */
        uint64_t preamble                     : 1;  /**< Send PREAMBLE on SMI transacton
                                                         PREAMBLE must be set 1 when MODE=1 in order
                                                         for the receiving PHY to correctly frame the
                                                         transaction. */
        uint64_t sample                       : 4;  /**< When to sample read data
                                                         (number of eclks after the rising edge of mdc)
                                                         ( [SAMPLE_HI,SAMPLE] > 1 )
                                                         ( [SAMPLE_HI, SAMPLE] + 3 <= 2*PHASE ) */
        uint64_t phase                        : 8;  /**< MDC Clock Phase
                                                         (number of eclks that make up an mdc phase)
                                                         (PHASE > 2) */
#else
        uint64_t phase                        : 8;
        uint64_t sample                       : 4;
        uint64_t preamble                     : 1;
        uint64_t clk_idle                     : 1;
        uint64_t reserved_14_14               : 1;
        uint64_t sample_mode                  : 1;
        uint64_t sample_hi                    : 5;
        uint64_t reserved_21_23               : 3;
        uint64_t mode                         : 1;
        uint64_t reserved_25_63               : 39;
#endif
        } s;
};
typedef union smix_clk smix_clk_t;

#endif /* __CAVM_CSRS_SMI__ */
