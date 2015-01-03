
#define DRV_NAME	"thunder_mmc"

#define thunder_MAX_MMC			4

#define OCT_MIO_NDF_DMA_CFG		0x00
#define OCT_MIO_EMM_DMA_ADR		0x08

#define OCT_MIO_EMM_CFG			0x00
#define OCT_MIO_EMM_SWITCH		0x48
#define OCT_MIO_EMM_DMA			0x50
#define OCT_MIO_EMM_CMD			0x58
#define OCT_MIO_EMM_RSP_STS		0x60
#define OCT_MIO_EMM_RSP_LO		0x68
#define OCT_MIO_EMM_RSP_HI		0x70
#define OCT_MIO_EMM_INT			0x78
#define OCT_MIO_EMM_INT_SET		0x80
#define OCT_MIO_EMM_WDOG		0x88
#define OCT_MIO_EMM_SAMPLE		0x90
#define OCT_MIO_EMM_STS_MASK		0x98
#define OCT_MIO_EMM_RCA			0xa0
#define OCT_MIO_EMM_INT_EN_SET		0xb0
#define OCT_MIO_EMM_INT_EN_CLR		0xb8
#define OCT_MIO_EMM_BUF_IDX		0xe0
#define OCT_MIO_EMM_BUF_DAT		0xe8

struct thunder_mmc_host {
	u64	base;
	u64	ndf_base;
	u64	emm_cfg;
	u64	n_minus_one;  /* thunder II workaround location */
	int	last_slot;

	struct semaphore mmc_serializer;
	struct mmc_request	*current_req;
	unsigned int		linear_buf_size;
	void			*linear_buf;
	struct sg_mapping_iter smi;
	int sg_idx;
	bool dma_active;

	struct platform_device	*pdev;
	int global_pwr_gpio;
	bool global_pwr_gpio_low;
	bool dma_err_pending;
	bool need_bootbus_lock;
	bool big_dma_addr;
	bool need_irq_handler_lock;
	spinlock_t irq_handler_lock;

	struct thunder_mmc_slot	*slot[thunder_MAX_MMC];
};

struct thunder_mmc_slot {
	struct mmc_host         *mmc;	/* slot-level mmc_core object */
	struct thunder_mmc_host	*host;	/* common hw for all 4 slots */

	unsigned int		clock;
	unsigned int		sclock;

	u64			cached_switch;
	u64			cached_rca;

	unsigned int		cmd_cnt; /* sample delay */
	unsigned int		dat_cnt; /* sample delay */

	int			bus_width;
	int			bus_id;
	int			ro_gpio;
	int			cd_gpio;
	int			pwr_gpio;
	bool			cd_gpio_low;
	bool			ro_gpio_low;
	bool			pwr_gpio_low;
};

union cvmx_mio_emm_cfg {
	uint64_t u64;
	struct cvmx_mio_emm_cfg_s {
	uint64_t bus_ena                      : 4;
        uint64_t reserved_4_15                : 12;
        uint64_t reserved_17_63               : 47;
        } s;
	struct cvmx_mio_emm_cfg_s	cn88xx;
};
typedef union cvmx_mio_emm_cfg cvmx_mio_emm_cfg_t;

union cvmx_mio_emm_int {
	uint64_t u64;
	struct cvmx_mio_emm_int_s {
	uint64_t buf_done                     : 1;
        uint64_t cmd_done                     : 1;
        uint64_t dma_done                     : 1;
        uint64_t cmd_err                      : 1;
        uint64_t dma_err                      : 1;
        uint64_t switch_done                  : 1;
        uint64_t switch_err                   : 1;
        uint64_t reserved_7_63                : 57;
	} s;
	struct cvmx_mio_emm_int_s	cn88xx;
};
typedef union cvmx_mio_emm_int cvmx_mio_emm_int_t;

union cvmx_mio_emm_dma {
        uint64_t u64;
        struct cvmx_mio_emm_dma_s {
	uint64_t card_addr                    : 32;
        uint64_t block_cnt                    : 16;
        uint64_t multi                        : 1;
        uint64_t rw                           : 1;
        uint64_t rel_wr                       : 1;
        uint64_t thres                        : 6;
        uint64_t dat_null                     : 1;
        uint64_t sector                       : 1;
        uint64_t dma_val                      : 1;
        uint64_t bus_id                       : 2;
        uint64_t skip_busy                    : 1;
        uint64_t reserved_63_63               : 1;
        } s;
	struct cvmx_mio_emm_dma_s	cn88xx;
};
typedef union cvmx_mio_emm_dma cvmx_mio_emm_dma_t;

union cvmx_mio_ndf_dma_cfg {
        uint64_t u64;
        struct cvmx_mio_ndf_dma_cfg_s {
        uint64_t adr                          : 36;
        uint64_t size                         : 20;
        uint64_t endian                       : 1;
        uint64_t swap8                        : 1;
        uint64_t swap16                       : 1;
        uint64_t swap32                       : 1;
        uint64_t reserved_60_60               : 1;
        uint64_t clr                          : 1;
        uint64_t rw                           : 1;
        uint64_t en                           : 1;
        } s;
        struct cvmx_mio_ndf_dma_cfg_s         cn88xx;
};
typedef union cvmx_mio_ndf_dma_cfg cvmx_mio_ndf_dma_cfg_t;

union cvmx_mio_emm_cmd {
        uint64_t u64;
        struct cvmx_mio_emm_cmd_s {
        uint64_t arg                          : 32;
        uint64_t cmd_idx                      : 6;
        uint64_t rtype_xor                    : 3;
        uint64_t ctype_xor                    : 2;
        uint64_t reserved_43_48               : 6;
        uint64_t offset                       : 6;
        uint64_t dbuf                         : 1;
        uint64_t reserved_56_58               : 3;
        uint64_t cmd_val                      : 1;
        uint64_t bus_id                       : 2;
        uint64_t skip_busy                    : 1;
        uint64_t reserved_63_63               : 1;
        } s;
	struct cvmx_mio_emm_cmd_s	cn88xx;
};
typedef union cvmx_mio_emm_cmd cvmx_mio_emm_cmd_t;

union cvmx_mio_emm_switch {
        uint64_t u64;
        struct cvmx_mio_emm_switch_s {
	        uint64_t clk_lo                       : 16;
        uint64_t clk_hi                       : 16;
        uint64_t power_class                  : 4;
        uint64_t reserved_36_39               : 4;
        uint64_t bus_width                    : 3;
        uint64_t reserved_43_47               : 5;
        uint64_t hs_timing                    : 1;
        uint64_t reserved_49_55               : 7;
        uint64_t switch_err2                  : 1;
        uint64_t switch_err1                  : 1;
        uint64_t switch_err0                  : 1;
        uint64_t switch_exe                   : 1;
        uint64_t bus_id                       : 2;
        uint64_t reserved_62_63               : 2;
        } s;
        struct cvmx_mio_emm_switch_s          cn88xx;
};
typedef union cvmx_mio_emm_switch cvmx_mio_emm_switch_t;

union cvmx_mio_emm_rsp_sts {
        uint64_t u64;
        struct cvmx_mio_emm_rsp_sts_s {
        uint64_t cmd_done                     : 1;
        uint64_t cmd_idx                      : 6;
        uint64_t cmd_type                     : 2;
        uint64_t rsp_type                     : 3;
        uint64_t rsp_val                      : 1;
        uint64_t rsp_bad_sts                  : 1;
        uint64_t rsp_crc_err                  : 1;
        uint64_t rsp_timeout                  : 1;
        uint64_t stp_val                      : 1;
        uint64_t stp_bad_sts                  : 1;
        uint64_t stp_crc_err                  : 1;
        uint64_t stp_timeout                  : 1;
        uint64_t rsp_busybit                  : 1;
        uint64_t blk_crc_err                  : 1;
        uint64_t blk_timeout                  : 1;
        uint64_t dbuf                         : 1;
        uint64_t reserved_24_27               : 4;
        uint64_t dbuf_err                     : 1;
        uint64_t reserved_29_54               : 26;
        uint64_t acc_timeout                  : 1;
        uint64_t dma_pend                     : 1;
        uint64_t dma_val                      : 1;
        uint64_t switch_val                   : 1;
        uint64_t cmd_val                      : 1;
        uint64_t bus_id                       : 2;
        uint64_t reserved_62_63               : 2;
        } s;
	struct cvmx_mio_emm_rsp_sts_s	cn88xx;
};
typedef union cvmx_mio_emm_rsp_sts cvmx_mio_emm_rsp_sts_t;

union cvmx_mio_emm_sample { 
        uint64_t u64;
        struct cvmx_mio_emm_sample_s {
        uint64_t dat_cnt                      : 10;
        uint64_t reserved_10_15               : 6;
        uint64_t cmd_cnt                      : 10;
        uint64_t reserved_26_63               : 38;
        } s;
        struct cvmx_mio_emm_sample_s          cn88xx;
};
typedef union cvmx_mio_emm_sample cvmx_mio_emm_sample_t;
